"""The read-projection contract: same decisions, fewer bytes.

These tests exist to prove one thing above all: a projection is a *serialization*
choice, never an authorization one. A compact read must agree with the full read
about identity, revision, visibility, and effective permissions; must keep a
concealed id indistinguishable from a missing one; and must never publish a
field a discover-only stub does not already publish.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Annotated, Any

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from synthetic_projection_catalog import (
    SyntheticCatalog,
    build_synthetic_catalog,
    synthetic_read_access,
)

from blockwart.api.deps import get_session
from blockwart.api.security import require_api_read_access
from blockwart.db.session import transaction
from blockwart.domain.auth import Permission
from blockwart.domain.read_projection import (
    CORE_SECTIONS,
    DEFAULT_PROJECTION_PROFILE,
    PROJECTION_PROFILES,
    PROJECTION_SECTIONS,
    READ_PROJECTION_VERSION,
    ReadProjectionError,
    capability_set_key,
    capability_set_permissions,
    resolve_read_projection,
)
from blockwart.main import create_app
from blockwart.services.read_access import ReadAccess

MISSING_ID = "synthetic-object-that-does-not-exist"


@pytest.fixture
def synthetic_catalog(alembic_session_factory) -> SyntheticCatalog:
    with alembic_session_factory() as session:
        with transaction(session):
            return build_synthetic_catalog(session)


def _client(
    alembic_session_factory,
    access: ReadAccess,
) -> Generator[TestClient, None, None]:
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with alembic_session_factory() as session:
            yield session

    def override_access(
        session: Annotated[Session, Depends(get_session)],
    ) -> ReadAccess:
        del session
        return access

    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[require_api_read_access] = override_access
    with TestClient(app) as client:
        yield client


@pytest.fixture
def client(
    alembic_session_factory,
    synthetic_catalog: SyntheticCatalog,
) -> Generator[TestClient, None, None]:
    yield from _client(
        alembic_session_factory,
        synthetic_read_access(synthetic_catalog),
    )


@pytest.fixture
def mixed_client(
    alembic_session_factory,
    synthetic_catalog: SyntheticCatalog,
) -> Generator[tuple[TestClient, SyntheticCatalog, dict[str, frozenset[str]]], None, None]:
    """One reader with readable, discover-only, and concealed objects at once."""
    scopes = {
        "stub": frozenset(synthetic_catalog.service_ids[:3]),
        "concealed": frozenset(synthetic_catalog.service_ids[3:6]),
    }
    access = synthetic_read_access(
        synthetic_catalog,
        stub_ids=scopes["stub"],
        concealed_ids=scopes["concealed"],
    )
    for test_client in _client(alembic_session_factory, access):
        yield test_client, synthetic_catalog, scopes


# --------------------------------------------------------------------------
# The resolved contract itself
# --------------------------------------------------------------------------


def test_omitting_every_projection_argument_resolves_to_the_unchanged_contract() -> None:
    for surface in ("summary", "context"):
        assert resolve_read_projection(surface=surface).is_default
        # An explicit `full` without a mask must stay indistinguishable from
        # sending nothing, so an explicit default never changes a response.
        assert resolve_read_projection(surface=surface, profile="full").is_default


def test_a_field_mask_can_only_narrow_the_chosen_profile() -> None:
    compact = resolve_read_projection(surface="context", profile="compact")
    masked = resolve_read_projection(
        surface="context",
        profile="compact",
        fields=list(PROJECTION_SECTIONS),
    )

    assert masked.sections == compact.sections
    assert "detail" not in masked.sections
    assert "activity" not in masked.sections


def test_the_field_mask_vocabulary_is_closed_and_excludes_the_core() -> None:
    with pytest.raises(ReadProjectionError):
        resolve_read_projection(surface="summary", fields=["data"])
    for core_section in CORE_SECTIONS:
        assert core_section not in PROJECTION_SECTIONS
        with pytest.raises(ReadProjectionError):
            resolve_read_projection(surface="summary", fields=[core_section])


def test_every_descriptor_names_the_core_sections_and_the_contract_version() -> None:
    for profile in PROJECTION_PROFILES:
        descriptor = resolve_read_projection(surface="context", profile=profile).descriptor()

        assert descriptor["version"] == READ_PROJECTION_VERSION
        assert descriptor["profile"] == profile
        assert descriptor["sections"][: len(CORE_SECTIONS)] == list(CORE_SECTIONS)


def test_distinct_effective_permission_sets_never_share_a_capability_key() -> None:
    seen: dict[str, frozenset[Permission]] = {}
    candidates = [
        frozenset(),
        frozenset({Permission.DISCOVER}),
        frozenset({Permission.DISCOVER, Permission.READ}),
        frozenset({Permission.DISCOVER, Permission.READ, Permission.WRITE}),
        frozenset(Permission),
    ]
    for permissions in candidates:
        key = capability_set_key(permissions)
        assert key not in seen or seen[key] == permissions
        seen[key] = permissions
        assert frozenset(capability_set_permissions(key)) == permissions

    assert len(seen) == len(candidates)


# --------------------------------------------------------------------------
# Compact and full must agree on every authorization-relevant fact
# --------------------------------------------------------------------------


def _by_id(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in items}


@pytest.mark.parametrize("profile", ["compact", "context"])
def test_projected_and_full_reads_agree_on_identity_revision_and_permissions(
    mixed_client: tuple[TestClient, SyntheticCatalog, dict[str, frozenset[str]]],
    profile: str,
) -> None:
    client, catalog, _ = mixed_client
    object_ids = catalog.batch_ids

    full = _by_id(
        client.post("/api/v1/object-contexts", json={"object_ids": object_ids}).json()["objects"]
    )
    projected_payload = client.post(
        "/api/v1/object-contexts",
        json={"object_ids": object_ids, "projection": profile},
    ).json()
    projected = _by_id(projected_payload["objects"])
    capability_sets = projected_payload["capability_sets"]

    assert set(projected) == set(full)
    for object_id, projected_item in projected.items():
        full_item = full[object_id]
        assert projected_item["visibility"] == full_item["visibility"]
        if projected_item["visibility"] == "concealed":
            continue
        assert projected_item["ref"] == full_item["ref"]
        assert projected_item["kind"] == full_item["kind"]
        assert projected_item["label"] == full_item["label"]
        # The effective permissions must resolve to exactly the full list.
        assert capability_sets[projected_item["capability_set"]] == full_item["capabilities"]
        if projected_item["visibility"] == "detail":
            assert projected_item["revision"] == full_item["revision"]
            assert projected_item["status"] == full_item["status"]


def test_a_projected_read_preserves_the_write_ready_etag_when_detail_is_selected(
    client: TestClient,
    synthetic_catalog: SyntheticCatalog,
) -> None:
    object_ids = synthetic_catalog.batch_ids
    full = _by_id(
        client.post("/api/v1/object-contexts", json={"object_ids": object_ids}).json()["objects"]
    )
    projected = _by_id(
        client.post(
            "/api/v1/object-contexts",
            json={"object_ids": object_ids, "projection": "context"},
        ).json()["objects"]
    )

    for object_id, item in projected.items():
        assert item["etag"] == full[object_id]["etag"]
        assert item["etag"] == f'"rev-{item["revision"]}"'


def test_a_projected_read_keeps_the_visible_parent_decision_of_the_full_read(
    mixed_client: tuple[TestClient, SyntheticCatalog, dict[str, frozenset[str]]],
) -> None:
    client, catalog, _ = mixed_client
    object_ids = catalog.batch_ids

    full = _by_id(
        client.post("/api/v1/object-contexts", json={"object_ids": object_ids}).json()["objects"]
    )
    compact = _by_id(
        client.post(
            "/api/v1/object-contexts",
            json={"object_ids": object_ids, "projection": "compact"},
        ).json()["objects"]
    )

    for object_id, item in compact.items():
        full_item = full[object_id]
        if full_item["visibility"] == "concealed":
            continue
        full_parent = full_item.get("parent")
        assert item.get("parent_ref") == (None if full_parent is None else full_parent["ref"])


# --------------------------------------------------------------------------
# Concealment must survive every profile and every field mask
# --------------------------------------------------------------------------


@pytest.mark.parametrize("profile", ["compact", "context", "full"])
def test_concealed_and_missing_ids_stay_indistinguishable_under_every_profile(
    mixed_client: tuple[TestClient, SyntheticCatalog, dict[str, frozenset[str]]],
    profile: str,
) -> None:
    client, _, scopes = mixed_client
    concealed_id = sorted(scopes["concealed"])[0]

    payload = client.post(
        "/api/v1/object-contexts",
        json={
            "object_ids": [concealed_id, MISSING_ID],
            "projection": profile,
            "fields": ["knowledge", "detail"],
        },
    ).json()
    concealed_item, missing_item = payload["objects"]

    assert set(concealed_item) == set(missing_item) == {"id", "visibility"}
    assert concealed_item["visibility"] == missing_item["visibility"] == "concealed"
    assert concealed_item["id"] == concealed_id
    assert missing_item["id"] == MISSING_ID
    # A concealed id contributes nothing to the shared capability table, so the
    # table cannot become an existence oracle either.
    assert payload["capability_sets"] == {}


def test_a_discover_only_stub_publishes_no_more_under_a_projection(
    mixed_client: tuple[TestClient, SyntheticCatalog, dict[str, frozenset[str]]],
) -> None:
    client, _, scopes = mixed_client
    stub_id = sorted(scopes["stub"])[0]

    full_stub = client.post(
        "/api/v1/object-contexts",
        json={"object_ids": [stub_id]},
    ).json()["objects"][0]
    projected_stub = client.post(
        "/api/v1/object-contexts",
        json={"object_ids": [stub_id], "projection": "context"},
    ).json()["objects"][0]

    assert full_stub["visibility"] == projected_stub["visibility"] == "stub"
    # Nothing a readable object publishes may appear on a projected stub.
    forbidden = {
        "status",
        "revision",
        "summary",
        "search_snippet",
        "data",
        "etag",
        "provenance",
        "monitoring",
        "relationships",
        "endpoints",
        "recent_comments",
    }
    assert not forbidden & set(projected_stub)


# --------------------------------------------------------------------------
# Type-aware compact projections
# --------------------------------------------------------------------------


def test_the_compact_projection_publishes_only_its_own_kind_knowledge_block(
    client: TestClient,
    synthetic_catalog: SyntheticCatalog,
) -> None:
    payload = client.get("/api/v1/objects?limit=50&projection=compact").json()
    items = _by_id(payload["items"])

    runbook = items[synthetic_catalog.runbook_ids[0]]
    decision = items[synthetic_catalog.decision_ids[0]]
    project = items[synthetic_catalog.project_ids[0]]
    host = items[synthetic_catalog.host_ids[0]]

    assert runbook["runbook_status"] == "active"
    assert runbook["runbook_risk"] == "disruptive"
    assert runbook["runbook_applies_to"]
    assert not {"decision_status", "project_status", "project_category"} & set(runbook)

    assert decision["decision_status"] == "accepted"
    assert decision["applies_to"]
    assert not {"runbook_status", "project_status"} & set(decision)

    assert project["project_category"] == "migration"
    assert project["project_status"] == "active"
    assert project["related_assets"]
    assert not {"runbook_status", "decision_status"} & set(project)

    # An asset kind carries no knowledge block at all.
    assert not {
        "decision_status",
        "runbook_status",
        "project_status",
        "project_category",
        "applies_to",
        "related_assets",
        "runbook_applies_to",
    } & set(host)


def test_the_knowledge_section_can_be_masked_away(
    client: TestClient,
    synthetic_catalog: SyntheticCatalog,
) -> None:
    payload = client.get("/api/v1/objects?limit=50&projection=compact&fields=orientation").json()
    runbook = _by_id(payload["items"])[synthetic_catalog.runbook_ids[0]]

    assert payload["projection"]["sections"] == ["identity", "state", "orientation"]
    assert "runbook_status" not in runbook
    # Identity and state survive every mask.
    assert runbook["ref"] and runbook["revision"] and runbook["capability_set"]


@pytest.mark.parametrize(
    ("endpoint", "limit"),
    [
        ("/api/v1/objects", 10),
        ("/api/v1/context", 5),
    ],
)
def test_an_explicit_empty_field_mask_is_core_only_and_preserves_read_decisions(
    mixed_client: tuple[TestClient, SyntheticCatalog, dict[str, frozenset[str]]],
    endpoint: str,
    limit: int,
) -> None:
    """`fields=` is distinct from omitting fields on every MCP-backed GET read."""
    client, _, scopes = mixed_client
    full = client.get(f"{endpoint}?limit={limit}&sort=id").json()
    core_only = client.get(f"{endpoint}?limit={limit}&sort=id&fields=").json()

    assert "projection" not in full
    assert core_only["projection"] == {
        "version": READ_PROJECTION_VERSION,
        "profile": "full",
        "sections": list(CORE_SECTIONS),
    }
    assert core_only["next_cursor"] == full["next_cursor"]
    assert core_only["total"] == full["total"]
    assert core_only["sort"] == full["sort"] == "id"
    assert core_only["direction"] == full["direction"] == "asc"

    full_items = _by_id(full["items"])
    core_items = _by_id(core_only["items"])
    assert set(core_items) == set(full_items)
    assert not set(scopes["concealed"]) & set(core_items)
    for object_id, item in core_items.items():
        full_item = full_items[object_id]
        assert item["visibility"] == full_item["visibility"]
        assert item["ref"] == full_item["ref"]
        assert item["kind"] == full_item["kind"]
        assert item["label"] == full_item["label"]
        assert item["capability_set"] in core_only["capability_sets"]
        assert core_only["capability_sets"][item["capability_set"]] == full_item["capabilities"]
        if item["visibility"] == "detail":
            assert item["revision"] == full_item["revision"]
            assert item["status"] == full_item["status"]
            assert "summary" not in item
            assert "data" not in item


# --------------------------------------------------------------------------
# The comment preview is explicit, and list_comments stays complete
# --------------------------------------------------------------------------


def test_the_comment_preview_is_explicit_and_list_comments_stays_complete(
    client: TestClient,
    synthetic_catalog: SyntheticCatalog,
) -> None:
    object_id = synthetic_catalog.host_ids[0]

    without = client.get(
        f"/api/v1/context?q={object_id}&limit=1&include_recent_comments=false"
    ).json()
    compact_with_preview = client.get(
        f"/api/v1/context?q={object_id}&limit=1&projection=compact&include_recent_comments=true"
    ).json()

    assert "activity" not in without["projection"]["sections"]
    assert "recent_comments" not in without["items"][0]
    # The preview can be switched back on independently of the profile, so a
    # compact read can still carry it when the agent explicitly wants it.
    assert "activity" in compact_with_preview["projection"]["sections"]
    assert "recent_comments" in compact_with_preview["items"][0]

    # Asking for the full profile with the preview on is the default read, so
    # it stays byte-identical to sending no projection argument at all.
    default = client.get(f"/api/v1/context?q={object_id}&limit=1")
    explicit_default = client.get(
        f"/api/v1/context?q={object_id}&limit=1&include_recent_comments=true"
    )
    assert explicit_default.content == default.content

    # The complete authorized history keeps its own unchanged surface.
    history = client.get(f"/api/v1/objects/{object_id}/comments")
    assert history.status_code == 200
    assert "items" in history.json()


def test_the_default_context_read_still_carries_its_comment_preview(
    client: TestClient,
    synthetic_catalog: SyntheticCatalog,
) -> None:
    object_id = synthetic_catalog.host_ids[0]

    payload = client.get(f"/api/v1/context?q={object_id}&limit=1").json()

    assert "projection" not in payload
    assert "recent_comments" in payload["items"][0]


# --------------------------------------------------------------------------
# Paging, ordering, and cursors are unaffected
# --------------------------------------------------------------------------


def test_a_projection_changes_no_result_ordering_and_no_cursor(
    client: TestClient,
) -> None:
    full = client.get("/api/v1/objects?limit=10&sort=id&include_total=true").json()
    compact = client.get(
        "/api/v1/objects?limit=10&sort=id&include_total=true&projection=compact"
    ).json()

    assert [item["id"] for item in compact["items"]] == [item["id"] for item in full["items"]]
    assert compact["next_cursor"] == full["next_cursor"]
    assert compact["total"] == full["total"]
    assert compact["sort"] == full["sort"]
    assert compact["direction"] == full["direction"]


def test_a_cursor_stays_valid_across_a_change_of_projection(
    client: TestClient,
) -> None:
    """A cursor addresses a result set, not a serialization of one."""
    first = client.get("/api/v1/objects?limit=10&sort=id&projection=compact").json()
    cursor = first["next_cursor"]
    assert cursor

    resumed_full = client.get(f"/api/v1/objects?limit=10&sort=id&cursor={cursor}").json()
    resumed_compact = client.get(
        f"/api/v1/objects?limit=10&sort=id&cursor={cursor}&projection=compact"
    ).json()

    assert [item["id"] for item in resumed_full["items"]] == [
        item["id"] for item in resumed_compact["items"]
    ]


def test_an_unknown_projection_or_field_is_rejected_by_the_published_contract(
    client: TestClient,
) -> None:
    assert client.get("/api/v1/objects?projection=everything").status_code == 422
    assert client.get("/api/v1/objects?fields=data").status_code == 422
    assert (
        client.post(
            "/api/v1/object-contexts",
            json={"object_ids": ["synthetic-host-01"], "projection": "everything"},
        ).status_code
        == 422
    )


def test_the_default_search_and_batch_responses_are_byte_for_byte_unchanged(
    client: TestClient,
    synthetic_catalog: SyntheticCatalog,
) -> None:
    """The historical contract must not gain a projection descriptor."""
    search = client.get("/api/v1/objects?limit=5")
    batch = client.post(
        "/api/v1/object-contexts",
        json={"object_ids": list(synthetic_catalog.host_ids)},
    )
    explicit_default = client.get(
        f"/api/v1/objects?limit=5&projection={DEFAULT_PROJECTION_PROFILE}"
    )

    assert set(search.json()) == {"items", "next_cursor", "total", "sort", "direction"}
    assert set(batch.json()) == {"objects", "count"}
    assert explicit_default.content == search.content
    assert all("capabilities" in item for item in search.json()["items"])
