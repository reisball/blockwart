"""Proof for the authorized catalog-wide agent activity feed (#188).

Every fixture is synthetic and documentation-safe. No private inventory count,
endpoint, path, credential, token, or instance mapping is part of this file.
The feed consumes ``audit_events`` rows exactly as the reviewed writers record
them, so deterministic direct rows are a faithful input contract here.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

import blockwart.api.routes.v1 as v1_routes
import blockwart.services.activity as activity_service
import blockwart.ui.routes as ui_routes
from blockwart.api.deps import get_session
from blockwart.domain.activity import classify_activity_event_type
from blockwart.domain.auth import Permission, PrincipalContext, PrincipalType
from blockwart.main import create_app
from blockwart.mcp.server import TOOLS, call_tool
from blockwart.models import AuditEvent, Relationship
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import delete_object, upsert_object
from blockwart.services.pagination import InvalidCursor
from blockwart.services.policy import PolicySnapshot
from blockwart.services.read_access import ReadAccess

NOW = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)


def _access(
    principal_id: str = "reader",
    readable: set[str] | None = None,
    *,
    discoverable: set[str] | None = None,
) -> ReadAccess:
    permissions: dict[str, frozenset[Permission]] = {
        object_id: frozenset({Permission.DISCOVER, Permission.READ})
        for object_id in (readable or set())
    }
    for object_id in discoverable or set():
        permissions.setdefault(object_id, frozenset({Permission.DISCOVER}))
    return ReadAccess(
        principal=PrincipalContext(
            id=principal_id,
            principal_type=PrincipalType.HUMAN,
            login=principal_id,
            display_name=principal_id,
        ),
        policy=PolicySnapshot(
            principal_id=principal_id,
            _permissions=permissions,
            _grants={},
        ),
    )


def _asset(object_id: str, kind: str = "host") -> CatalogObjectIn:
    document = {"schema_version": 1}
    if kind in {"system", "service"}:
        document["placement"] = {
            "state": "unassigned",
            "reason": "Synthetic standalone fixture.",
        }
    return CatalogObjectIn.model_validate(
        {
            "id": object_id,
            "kind": kind,
            "label": object_id.replace("-", " ").title(),
            "lifecycle": "active",
            "health": "healthy",
            "data": document,
        }
    )


def _seed(
    session: Session,
    object_id: str,
    kind: str = "host",
    *,
    created_at: datetime,
) -> None:
    """Create one object plus its revision audit row at a fixed timestamp."""
    upsert_object(session, _asset(object_id, kind), write_audit=False)
    session.add(_audit(object_id, "create", created_at=created_at))


def _audit(
    object_id: str,
    action: str,
    *,
    created_at: datetime,
    actor: str = "tester",
    details: dict | None = None,
    sequence: int = 0,
) -> AuditEvent:
    """One deterministic audit row exactly as the reviewed writers shape it."""
    return AuditEvent(
        id=None,
        object_id=object_id,
        action=action,
        actor=actor,
        summary=action,
        created_at=created_at.replace(tzinfo=None),
        details_json=json.dumps(
            {
                "event": action,
                "version": 1,
                "object_ref": f"host:{object_id}" if action != "comment_create" else None,
                **(details or {}),
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
    )


def _page(session: Session, access: ReadAccess, **kwargs):
    kwargs.setdefault("now", NOW)
    kwargs.setdefault("include_total", True)
    return activity_service.query_activity_page(session, access, **kwargs)


def _types(page) -> list[str]:
    return [item.event_type for item in page.items]


def test_equal_timestamps_keep_a_stable_newest_first_order(
    alembic_session_factory,
) -> None:
    same_instant = NOW - timedelta(minutes=1)
    with alembic_session_factory() as session, session.begin():
        upsert_object(session, _asset("stable-one"))
        upsert_object(session, _asset("stable-two"))
        for sequence, object_id in ((1, "stable-one"), (2, "stable-two")):
            session.add(
                _audit(
                    object_id,
                    "update",
                    created_at=same_instant,
                    sequence=sequence,
                )
            )

    with alembic_session_factory() as session:
        newest_first = _page(session, _access(readable={"stable-one", "stable-two"}))
        oldest_first = _page(
            session,
            _access(readable={"stable-one", "stable-two"}),
            direction="asc",
        )

    # Same timestamp: the zero-padded event id tie-breaker keeps one stable,
    # deterministic order; no item ever swaps between runs.
    def _updates(items):
        return [
            i.event_id
            for i in items
            if i.event_type == "object_revision"
            and i.summary.startswith("Updated host:stable")
        ]

    # Both update rows share one timestamp; the zero-padded event id
    # tie-breaker keeps one stable order in both directions.
    update_ids_desc = _updates(newest_first.items)
    update_ids_asc = _updates(oldest_first.items)
    assert len(update_ids_desc) == 2
    assert update_ids_desc == sorted(update_ids_desc, reverse=True)
    assert update_ids_asc == sorted(update_ids_desc)
    keys = [item.key for item in oldest_first.items]
    assert keys == sorted(keys)


def test_comment_is_visible_while_the_faceted_updated_at_stays_unchanged(
    alembic_session_factory,
) -> None:
    comment_time = NOW - timedelta(minutes=2)
    with alembic_session_factory() as session, session.begin():
        upsert_object(session, _asset("quiet-service", kind="service"))
        # The catalog row keeps its original updated_at: only the feed sees it.
        session.add(_audit("quiet-service", "comment_create", created_at=comment_time))

    with alembic_session_factory() as session:
        page = _page(
            session,
            _access(readable={"quiet-service"}),
            event_type="comment_create",
        )

    assert [item.event_type for item in page.items] == ["comment_create"]
    item = page.items[0]
    assert item.object.ref == "service:quiet-service"
    assert item.detail_path == "/api/v1/objects/quiet-service/comments"
    # The envelope never carries the comment body.
    assert not hasattr(item, "body")


def test_concealed_objects_influence_nothing(alembic_session_factory) -> None:
    hidden_time = NOW - timedelta(minutes=3)
    with alembic_session_factory() as session, session.begin():
        for object_id in ("open-object", "hidden-object", "stub-object"):
            _seed(session, object_id, created_at=hidden_time)
            session.add(_audit(object_id, "update", created_at=hidden_time))

    with alembic_session_factory() as session:
        full_access = _access(readable={"open-object", "hidden-object", "stub-object"})
        restricted = _page(session, _access(readable={"open-object"}))
        discover_only = _page(
            session,
            _access(
                readable={"open-object"},
                discoverable={"hidden-object"},
            ),
        )
        baseline = _page(session, full_access)

    assert [item.object.object_id for item in restricted.items] == [
        "open-object",
        "open-object",
    ]
    assert restricted.total == 2
    # Discover-only stubs are not detail-visible and therefore never appear.
    assert all(item.object.object_id != "hidden-object" for item in discover_only.items)
    # A concealed object is simply absent; it cannot reorder or re-count the
    # remaining authorized items.
    assert {item.object.object_id for item in baseline.items} == {
        "open-object",
        "hidden-object",
        "stub-object",
    }
    assert baseline.total == 6


def test_deleted_objects_fail_closed(alembic_session_factory) -> None:
    delete_time = NOW - timedelta(minutes=4)
    with alembic_session_factory() as session, session.begin():
        _seed(session, "gone-host", created_at=delete_time)
        _seed(session, "kept-host", created_at=delete_time)
        session.add(_audit("gone-host", "update", created_at=delete_time))

    with alembic_session_factory() as session, session.begin():
        access = _access(readable={"gone-host", "kept-host"})
        before = _page(session, access)
        assert any(item.object.object_id == "gone-host" for item in before.items)
        assert delete_object(session, "gone-host") is True

    # After deletion the row is gone, so its history is no longer readable by
    # anyone: the drop is fail-closed, never a leaked deletion trace.
    with alembic_session_factory() as session:
        after = _page(session, _access(readable={"gone-host", "kept-host"}))
        assert {item.object.object_id for item in after.items} == {"kept-host"}
        unknown = _page(
            session,
            _access(readable={"gone-host"}),
            object_id="gone-host",
        )
        assert unknown.total == 0


def test_rights_loss_between_pages_fails_closed(alembic_session_factory) -> None:
    stamp = NOW - timedelta(minutes=5)
    with alembic_session_factory() as session, session.begin():
        upsert_object(session, _asset("page-a"))
        upsert_object(session, _asset("page-b"))
        for offset, object_id in enumerate(("page-a", "page-b")):
            session.add(
                _audit(object_id, "update", created_at=stamp - timedelta(seconds=offset))
            )

    with alembic_session_factory() as session:
        first = _page(
            session,
            _access(readable={"page-a", "page-b"}, principal_id="pager"),
            limit=1,
            direction="asc",
        )
        assert first.next_cursor

    with alembic_session_factory() as session:
        # The principal loses read access to page-b before requesting page two;
        # the stale cursor is rejected instead of silently skipping the gap.
        with pytest.raises(InvalidCursor):
            _page(
                session,
                _access(readable={"page-a"}, principal_id="pager"),
                limit=1,
                direction="asc",
                cursor=first.next_cursor,
            )
        fresh = _page(
            session,
            _access(readable={"page-a"}, principal_id="pager-2"),
            limit=1,
            direction="asc",
        )
        assert [item.object.object_id for item in fresh.items] == ["page-a"]


def test_pagination_cursor_boundaries_are_deterministic(
    alembic_session_factory,
) -> None:
    base = NOW - timedelta(minutes=6)
    with alembic_session_factory() as session, session.begin():
        ids = [f"paged-{index}" for index in range(5)]
        for index, object_id in enumerate(ids):
            _seed(session, object_id, created_at=base - timedelta(seconds=index))
            session.add(
                _audit(object_id, "update", created_at=base - timedelta(seconds=index))
            )

    access = _access(readable=set(ids), principal_id="walker")
    collected: list[str] = []
    pages = 0
    with alembic_session_factory() as session:
        cursor = None
        while True:
            page = _page(
                session,
                access,
                limit=2,
                direction="asc",
                cursor=cursor,
            )
            collected.extend(item.event_id for item in page.items)
            pages += 1
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
            assert pages < 10

    # Five creates plus five deterministic updates page two at a time.
    assert len(collected) == 10
    assert len(set(collected)) == 10
    assert pages == 5
    # Replaying an identical cursor returns the identical page.
    with alembic_session_factory() as session:
        replay_a = _page(session, access, limit=2, direction="asc")
        replay_b = _page(
            session,
            access,
            limit=2,
            direction="asc",
            cursor=replay_a.next_cursor,
        )
    assert [i.event_id for i in replay_b.items] == collected[2:4]


def test_filters_since_event_type_kind_parent_and_subtree(
    alembic_session_factory,
) -> None:
    base = NOW - timedelta(minutes=7)
    with alembic_session_factory() as session, session.begin():
        _seed(session, "parent-host", created_at=base)
        _seed(session, "child-system", kind="system", created_at=base)
        _seed(session, "other-host", created_at=base - timedelta(seconds=30))
        session.add(
            Relationship(
                from_ref="host:parent-host",
                relation_type="hosts",
                to_ref="system:child-system",
                metadata_json="{}",
            )
        )
        session.add(_audit("parent-host", "relationship_create", created_at=base))
        session.add(_audit("child-system", "update", created_at=base))
        session.add(_audit("other-host", "update", created_at=base - timedelta(seconds=30)))

    access = _access(readable={"parent-host", "child-system", "other-host"})
    with alembic_session_factory() as session:
        subtree = _page(session, access, parent="parent-host")
        since_stamp = (
            (base - timedelta(seconds=15))
            .replace(tzinfo=UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )
        since_only = _page(session, access, since=since_stamp)
        typed = _page(session, access, event_type="relationship_mutation")
        kinded = _page(session, access, kind="system")
        self_parent = _page(session, access, parent="other-host")
        unknown_parent = _page(session, access, parent="missing-object")

    assert {item.object.object_id for item in subtree.items} == {"parent-host", "child-system"}
    assert {item.object.object_id for item in since_only.items} == {
        "parent-host",
        "child-system",
    }
    assert _types(typed) == ["relationship_mutation"]
    assert {item.object.object_id for item in kinded.items} == {"child-system"}
    # A visible parent without descendants scopes to itself only.
    assert {item.object.object_id for item in self_parent.items} == {"other-host"}
    # An unknown parent resolves to an empty page indistinguishable from a
    # quiet parent: nothing about visibility leaks through the filter.
    assert unknown_parent.total == 0 and unknown_parent.items == []


def test_classification_covers_the_closed_vocabulary() -> None:
    assert classify_activity_event_type("create") == "object_revision"
    assert classify_activity_event_type("delete") == "object_revision"
    assert classify_activity_event_type("seed_update") == "object_revision"
    assert classify_activity_event_type("relationship_delete") == "relationship_mutation"
    assert classify_activity_event_type("comment_create") == "comment_create"
    assert classify_activity_event_type("grant_revoke") == "audit"
    assert classify_activity_event_type("placement_state_normalize") == "audit"


def test_more_events_than_scan_budget_stay_reachable_without_gaps_or_duplicates(
    alembic_session_factory,
    monkeypatch,
) -> None:
    # The scan budget is a documented size signal, not a hard cap: keyset
    # pagination must walk every matching event, so the 5001st event is
    # reachable and no event is skipped or duplicated.
    monkeypatch.setattr(activity_service, "ACTIVITY_MAX_SCAN_EVENTS", 3)
    base = NOW - timedelta(minutes=11)
    ids = [f"scan-{index}" for index in range(7)]
    with alembic_session_factory() as session, session.begin():
        for index, object_id in enumerate(ids):
            _seed(session, object_id, created_at=base - timedelta(seconds=index))

    access = _access(readable=set(ids), principal_id="scanner")
    collected: list[str] = []
    with alembic_session_factory() as session:
        cursor = None
        while True:
            page = _page(session, access, limit=2, direction="asc", cursor=cursor)
            collected.extend(item.event_id for item in page.items)
            if page.next_cursor is None:
                break
            cursor = page.next_cursor

    assert len(collected) == 7
    assert len(set(collected)) == 7


def test_include_total_reports_the_full_result_and_flags_budget_overshoot(
    alembic_session_factory,
    monkeypatch,
) -> None:
    monkeypatch.setattr(activity_service, "ACTIVITY_MAX_SCAN_EVENTS", 3)
    base = NOW - timedelta(minutes=12)
    ids = [f"total-{index}" for index in range(7)]
    with alembic_session_factory() as session, session.begin():
        for index, object_id in enumerate(ids):
            _seed(session, object_id, created_at=base - timedelta(seconds=index))

    with alembic_session_factory() as session:
        page = _page(session, _access(readable=set(ids)), limit=2, include_total=True)

    # The total is the exact authorized filtered count, never a page-sized window.
    assert page.total == 7
    assert page.total_exceeds_budget is True


def test_total_exceeds_budget_is_null_without_an_exact_count(
    alembic_session_factory,
    monkeypatch,
) -> None:
    monkeypatch.setattr(activity_service, "ACTIVITY_MAX_SCAN_EVENTS", 3)
    base = NOW - timedelta(minutes=12, seconds=30)
    ids = [f"no-total-{index}" for index in range(7)]
    with alembic_session_factory() as session, session.begin():
        for index, object_id in enumerate(ids):
            _seed(session, object_id, created_at=base - timedelta(seconds=index))

    with alembic_session_factory() as session:
        page = _page(
            session,
            _access(readable=set(ids)),
            limit=2,
            include_total=False,
        )

    # Without an exact count the budget signal is undefined, never a false
    # positive: keyset pagination still reaches every matching row.
    assert page.total is None
    assert page.total_exceeds_budget is None


def test_total_exceeds_budget_is_false_when_exact_count_is_within_budget(
    alembic_session_factory,
    monkeypatch,
) -> None:
    monkeypatch.setattr(activity_service, "ACTIVITY_MAX_SCAN_EVENTS", 100)
    base = NOW - timedelta(minutes=12, seconds=45)
    ids = [f"within-{index}" for index in range(3)]
    with alembic_session_factory() as session, session.begin():
        for index, object_id in enumerate(ids):
            _seed(session, object_id, created_at=base - timedelta(seconds=index))

    with alembic_session_factory() as session:
        page = _page(session, _access(readable=set(ids)), limit=2, include_total=True)

    assert page.total == 3
    assert page.total_exceeds_budget is False


def test_new_event_between_pages_does_not_duplicate_or_gap(
    alembic_session_factory,
) -> None:
    base = NOW - timedelta(minutes=13)
    ids = [f"live-{index}" for index in range(5)]
    with alembic_session_factory() as session, session.begin():
        for index, object_id in enumerate(ids):
            _seed(session, object_id, created_at=base - timedelta(seconds=index))

    access = _access(readable=set(ids), principal_id="live")
    with alembic_session_factory() as session:
        first = _page(session, access, limit=2, direction="asc")
        assert first.next_cursor

    # A new audit event for an already-readable object lands between the two
    # page requests. It must not invalidate the continuation, duplicate an
    # already-seen event, or open a gap.
    with alembic_session_factory() as session, session.begin():
        session.add(
            _audit(
                "live-0",
                "update",
                created_at=base - timedelta(seconds=2, microseconds=500000),
            )
        )

    collected = [item.event_id for item in first.items]
    with alembic_session_factory() as session:
        cursor = first.next_cursor
        while True:
            page = _page(session, access, limit=2, direction="asc", cursor=cursor)
            collected.extend(item.event_id for item in page.items)
            if page.next_cursor is None:
                break
            cursor = page.next_cursor

    assert len(collected) == len(set(collected))
    assert len(collected) == 6


def test_cursor_binds_to_policy_fingerprint_across_principals(
    alembic_session_factory,
) -> None:
    stamp = NOW - timedelta(minutes=14)
    with alembic_session_factory() as session, session.begin():
        upsert_object(session, _asset("fp-a"))
        upsert_object(session, _asset("fp-b"))
        for offset, object_id in enumerate(("fp-a", "fp-b")):
            session.add(
                _audit(object_id, "update", created_at=stamp - timedelta(seconds=offset))
            )

    with alembic_session_factory() as session:
        first = _page(
            session,
            _access(readable={"fp-a", "fp-b"}, principal_id="alice"),
            limit=1,
            direction="asc",
        )
        assert first.next_cursor

    with alembic_session_factory() as session:
        # Same readable set, different principal: the policy fingerprint differs,
        # so the cursor is rejected instead of silently reused across principals.
        with pytest.raises(InvalidCursor):
            _page(
                session,
                _access(readable={"fp-a", "fp-b"}, principal_id="bob"),
                limit=1,
                direction="asc",
                cursor=first.next_cursor,
            )


def test_parent_subtree_ignores_unrelated_placement_relationships(
    alembic_session_factory,
) -> None:
    base = NOW - timedelta(minutes=15)
    with alembic_session_factory() as session, session.begin():
        _seed(session, "root-host", created_at=base)
        _seed(session, "child-system", kind="system", created_at=base)
        _seed(session, "unrelated-host", created_at=base)
        _seed(session, "unrelated-system", kind="system", created_at=base)
        session.add(
            Relationship(
                from_ref="host:root-host",
                relation_type="hosts",
                to_ref="system:child-system",
                metadata_json="{}",
            )
        )
        session.add(
            Relationship(
                from_ref="host:unrelated-host",
                relation_type="hosts",
                to_ref="system:unrelated-system",
                metadata_json="{}",
            )
        )
        for object_id in ("root-host", "child-system", "unrelated-host", "unrelated-system"):
            session.add(_audit(object_id, "update", created_at=base))

    access = _access(
        readable={"root-host", "child-system", "unrelated-host", "unrelated-system"}
    )
    with alembic_session_factory() as session:
        subtree = _page(session, access, parent="root-host")

    # The unrelated placement edge (unrelated-host -> unrelated-system) is not
    # part of root-host's subtree and must not leak into the parent scope.
    assert {item.object.object_id for item in subtree.items} == {
        "root-host",
        "child-system",
    }


def test_rest_ui_and_mcp_share_the_application_query(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session, session.begin():
        upsert_object(session, _asset("shared-surface"))

    app = create_app()
    install_unrestricted_read_access(app)

    def session_dependency():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = session_dependency
    with TestClient(app) as client:
        rest_response = client.get("/api/v1/activity", params={"limit": "5"})

        requested_paths: list[str] = []

        def fetch(path: str, params: dict) -> dict:
            requested_paths.append(path)
            response = client.get(
                path,
                params={key: value for key, value in params.items() if value is not None},
            )
            response.raise_for_status()
            return response.json()

        mcp_result = call_tool("blockwart.get_activity", {"limit": 5}, fetcher=fetch)
        english = client.get("/activity?lang=en")
        german = client.get("/activity?lang=de")
        invalid_type = client.get("/api/v1/activity", params={"event_type": "nope"})
        index = client.get("/?lang=en")

    assert rest_response.status_code == 200
    rest = rest_response.json()
    mcp = json.loads(mcp_result["content"][0]["text"])
    assert requested_paths == ["/api/v1/activity"]
    assert {key: value for key, value in mcp.items() if key != "generated_at"} == {
        key: value for key, value in rest.items() if key != "generated_at"
    }
    assert rest["sort"] == "occurred_at"
    assert rest["direction"] == "desc"
    assert rest["items"], "seeded create activity must be visible"
    envelope_keys = set(rest["items"][0])
    assert envelope_keys == {
        "event_id",
        "event_type",
        "occurred_at",
        "object",
        "summary",
        "actor",
        "detail_path",
    }
    assert english.status_code == german.status_code == 200
    assert "Activity" in english.text
    assert "Aktivität" in german.text
    assert 'href="/activity"' in index.text
    assert invalid_type.status_code == 422
    assert v1_routes.query_activity_page is activity_service.query_activity_page
    assert ui_routes.query_activity_page is activity_service.query_activity_page

    tool = next(item for item in TOOLS if item["name"] == "blockwart.get_activity")
    assert tool["annotations"]["readOnlyHint"] is True
    assert tool["inputSchema"]["properties"]["direction"]["default"] == "desc"
