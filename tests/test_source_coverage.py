from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from blockwart.api.deps import get_session
from blockwart.api.security import require_api_read_access
from blockwart.cli import import_markdown as import_markdown_cli
from blockwart.db.session import transaction
from blockwart.domain.auth import Permission, PlatformRole, PrincipalContext, PrincipalType
from blockwart.domain.source_coverage import (
    COVERAGE_STATES,
    CatalogTarget,
    SourceCoverageError,
    SourceEntry,
    SourceMapping,
    SourceSnapshot,
    content_fingerprint,
    resolve_coverage,
    source_fingerprint,
)
from blockwart.main import create_app
from blockwart.models import CatalogObject
from blockwart.models.source_coverage import SourceEntry as SourceEntryRow
from blockwart.models.source_coverage import SourceSnapshot as SourceSnapshotRow
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import upsert_object
from blockwart.services.markdown_import import build_tools_import_plan
from blockwart.services.pagination import InvalidCursor
from blockwart.services.policy import PolicySnapshot
from blockwart.services.read_access import ReadAccess
from blockwart.services.source_coverage import (
    CoverageAuthorityDenied,
    load_current_snapshot,
    query_source_coverage_page,
    record_source_snapshot,
)

NOW = "2026-08-11T10:00:00Z"
LATER = "2026-08-11T11:00:00Z"


def _fingerprint(value: str) -> str:
    return content_fingerprint([value])


def _entry(
    entry_id: str,
    *,
    classification: str = "operational",
    intent: str = "expect_object",
    reason: str = "operational_inventory",
    presence: str = "present",
    fingerprint: str | None = None,
    mappings: tuple[SourceMapping, ...] = (),
) -> SourceEntry:
    return SourceEntry(
        source_uri="workspace://TOOLS.md",
        entry_id=entry_id,
        classification=classification,  # type: ignore[arg-type]
        intent=intent,  # type: ignore[arg-type]
        decision_reason=reason,  # type: ignore[arg-type]
        entry_fingerprint=fingerprint or _fingerprint(entry_id),
        source_fingerprint="0" * 64,
        observed_at=NOW,
        presence=presence,  # type: ignore[arg-type]
        mappings=mappings,
    )


def _snapshot(*entries: SourceEntry, collected_at: str = NOW) -> SourceSnapshot:
    aggregate = source_fingerprint(
        entry.entry_fingerprint
        for entry in entries
        if entry.presence == "present"
    )
    normalized = tuple(replace(entry, source_fingerprint=aggregate) for entry in entries)
    return SourceSnapshot(
        collector="markdown_tools",
        collected_at=collected_at,
        entries=normalized,
    ).with_digest()


def _mapping(
    object_id: str,
    fingerprint: str,
    *,
    role: str = "primary",
) -> SourceMapping:
    return SourceMapping(
        object_id=object_id,
        role=role,  # type: ignore[arg-type]
        imported_entry_fingerprint=fingerprint,
        imported_at=NOW,
        verified_at=NOW,
    )


def _targets(*rows: tuple[str, str, bool]) -> dict[str, CatalogTarget]:
    return {
        object_id: CatalogTarget(
            object_id=object_id,
            kind=kind,
            exists=True,
            is_stale=stale,
        )
        for object_id, kind, stale in rows
    }


def _access(
    principal_id: str,
    readable: set[str],
    *,
    admin: bool = False,
) -> ReadAccess:
    return ReadAccess(
        principal=PrincipalContext(
            id=principal_id,
            principal_type=PrincipalType.HUMAN,
            login=principal_id,
            display_name=principal_id,
            platform_role=PlatformRole.ADMIN if admin else None,
        ),
        policy=PolicySnapshot(
            principal_id=principal_id,
            _permissions={
                object_id: frozenset({Permission.DISCOVER, Permission.READ})
                for object_id in readable
            },
            _grants={},
        ),
    )


def test_domain_resolver_has_stable_complete_drift_vocabulary() -> None:
    current_fp = _fingerprint("current")
    old_fp = _fingerprint("old")
    entries = (
        _entry("current", fingerprint=current_fp, mappings=(_mapping("a", current_fp),)),
        _entry("stale", mappings=(_mapping("b", _fingerprint("stale")),)),
        _entry("new"),
        _entry(
            "research",
            classification="research",
            intent="no_catalog_object",
            reason="research_material",
        ),
        _entry("orphan", mappings=(_mapping("deleted", _fingerprint("orphan")),)),
        _entry(
            "missing",
            presence="absent",
            mappings=(_mapping("c", _fingerprint("missing")),),
        ),
        _entry(
            "ambiguous",
            mappings=(
                _mapping("d", _fingerprint("ambiguous")),
                _mapping("e", _fingerprint("ambiguous")),
            ),
        ),
        _entry("duplicate-a", mappings=(_mapping("shared", _fingerprint("duplicate-a")),)),
        _entry("duplicate-b", mappings=(_mapping("shared", _fingerprint("duplicate-b")),)),
        _entry("changed", fingerprint=current_fp, mappings=(_mapping("f", old_fp),)),
    )

    details = resolve_coverage(
        _snapshot(*entries),
        _targets(
            ("a", "host", False),
            ("b", "system", True),
            ("c", "service", False),
            ("d", "host", False),
            ("e", "service", False),
            ("shared", "service", False),
            ("f", "network", False),
        ),
    )

    states = {detail.entry_id: detail.state for detail in details}
    assert states == {
        "ambiguous": "ambiguous_mapping",
        "changed": "source_changed_since_import",
        "current": "mapped_current",
        "duplicate-a": "duplicate_mapping",
        "duplicate-b": "duplicate_mapping",
        "missing": "missing_source",
        "new": "unmapped_operational",
        "orphan": "orphaned_catalog_reference",
        "research": "intentionally_unmapped",
        "stale": "mapped_stale",
    }
    assert set(states.values()) == set(COVERAGE_STATES)


def test_markdown_dry_run_collects_new_and_explicitly_excluded_rows_without_catalog_write(
    tmp_path: Path,
    alembic_session_factory,
) -> None:
    tools = tmp_path / "TOOLS.md"
    tools.write_text(
        "\n".join(
            [
                "| Entry ID | System | Type | Classification | Decision Reason | Status |",
                "|---|---|---|---|---|---|",
                "| live-api | Live API | Service | operational | operational_inventory | ✅ |",
                "| old-note | Old note | Note | historical | historical_record | - |",
                "| paper | Research paper | Note | research | research_material | - |",
            ]
        ),
        encoding="utf-8",
    )
    with alembic_session_factory() as session:
        before = session.scalar(select(func.count()).select_from(CatalogObject))
        plan = build_tools_import_plan(tools, observed_at=NOW)
        after = session.scalar(select(func.count()).select_from(CatalogObject))

    details = resolve_coverage(plan.coverage_snapshot, {})
    assert before == after == 0
    assert {item.entry_id: item.state for item in details} == {
        "live-api": "unmapped_operational",
        "old-note": "intentionally_unmapped",
        "paper": "intentionally_unmapped",
    }
    assert plan.object_count == 1
    assert plan.coverage_snapshot.digest == build_tools_import_plan(
        tools,
        observed_at=LATER,
    ).coverage_snapshot.digest


def test_cli_can_record_only_the_dry_run_snapshot(
    tmp_path: Path,
    alembic_database,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tools = tmp_path / "TOOLS.md"
    tools.write_text(
        "\n".join(
            [
                "| Entry ID | System | Type | Classification | Status |",
                "|---|---|---|---|---|",
                "| new-api | New API | Service | operational | ✅ |",
            ]
        ),
        encoding="utf-8",
    )

    result = import_markdown_cli.main(
        [
            "--database-url",
            alembic_database.database_url,
            "--tools",
            str(tools),
            "--references-root",
            str(tmp_path),
            "--record-coverage",
        ]
    )

    assert result == 0
    output = capsys.readouterr().out
    assert "source_coverage_recorded digest=" in output
    assert '"unmapped_operational":1' in output
    with alembic_database.sessions() as session:
        assert session.scalar(select(func.count()).select_from(CatalogObject)) == 0
        assert session.scalar(select(func.count()).select_from(SourceSnapshotRow)) == 1


def test_snapshot_persistence_is_sanitized_deterministic_and_bounded(
    alembic_session_factory,
) -> None:
    first = _entry("b")
    second = _entry("a")
    snapshot = _snapshot(first, second)
    reordered = _snapshot(second, first, collected_at=LATER)
    assert snapshot.digest == reordered.digest

    with alembic_session_factory() as session, transaction(session):
        record_source_snapshot(session, reordered)
        record_source_snapshot(session, snapshot)
        assert session.scalar(select(func.count()).select_from(SourceSnapshotRow)) == 1
        stored = session.scalars(select(SourceEntryRow).order_by(SourceEntryRow.entry_key)).all()
        assert [row.entry_key for row in stored] == ["a", "b"]
        assert all(not hasattr(row, "content") for row in stored)

    secret_entry = replace(
        _entry("secret"),
        source_uri="https://example.invalid/Bearer%20abc",
        entry_id="ghp_abcdefghijklmnopqrstuvwxyz",
    )
    with alembic_session_factory() as session, transaction(session):
        with pytest.raises(SourceCoverageError):
            record_source_snapshot(session, _snapshot(secret_entry))

    secret_collector = replace(
        _snapshot(_entry("collector")),
        collector="ghp_abcdefghijklmnopqrstuvwxyz",
        digest="",
    ).with_digest()
    with alembic_session_factory() as session, transaction(session):
        with pytest.raises(SourceCoverageError):
            record_source_snapshot(session, secret_collector)


def test_markdown_duplicate_maximum_entry_ids_remain_bounded(tmp_path: Path) -> None:
    tools = tmp_path / "TOOLS.md"
    maximum_id = "a" * 256
    tools.write_text(
        "\n".join(
            [
                "| Entry ID | System | Type | Status |",
                "|---|---|---|---|",
                f"| {maximum_id} | First | Service | active |",
                f"| {maximum_id} | Second | Service | active |",
            ]
        ),
        encoding="utf-8",
    )

    snapshot = build_tools_import_plan(tools, observed_at=NOW).coverage_snapshot

    assert len(snapshot.entries) == 2
    assert all(entry.entry_id is not None for entry in snapshot.entries)
    assert all(len(entry.entry_id or "") <= 256 for entry in snapshot.entries)


def test_markdown_snapshot_accounts_for_inventory_and_tracks_renamed_entries(
    tmp_path: Path,
) -> None:
    tools = tmp_path / "TOOLS.md"
    tools.write_text(
        "\n".join(
            [
                "| Entry ID | System | Type | Classification | Status |",
                "|---|---|---|---|---|",
                "| original-entry | Original | Service | operational | active |",
                "| archive | Archive | Note | historical | retired |",
            ]
        ),
        encoding="utf-8",
    )
    first = build_tools_import_plan(
        tools,
        observed_at=NOW,
        mapped_object_ids=frozenset({"original"}),
    ).coverage_snapshot
    targets = _targets(("original", "service", False))

    assert {detail.state for detail in resolve_coverage(first, targets)} == {
        "mapped_current",
        "intentionally_unmapped",
    }
    assert first.digest == build_tools_import_plan(
        tools,
        observed_at=LATER,
        mapped_object_ids=frozenset({"original"}),
    ).coverage_snapshot.digest

    tools.write_text(
        "\n".join(
            [
                "| Entry ID | System | Type | Classification | Status |",
                "|---|---|---|---|---|",
                "| renamed-entry | Original | Service | operational | active |",
                "| archive | Archive | Note | historical | retired |",
            ]
        ),
        encoding="utf-8",
    )
    renamed = build_tools_import_plan(
        tools,
        observed_at=LATER,
        previous_snapshot=first,
        mapped_object_ids=frozenset({"original"}),
    ).coverage_snapshot

    states = {detail.entry_id: detail.state for detail in resolve_coverage(renamed, targets)}
    assert states == {
        "archive": "intentionally_unmapped",
        "original-entry": "missing_source",
        "renamed-entry": "mapped_current",
    }


def test_authorization_precedes_details_counts_and_cursor_binding(
    alembic_session_factory,
) -> None:
    visible_fp = _fingerprint("visible")
    hidden_fp = _fingerprint("hidden")
    mixed_fp = _fingerprint("mixed")
    with alembic_session_factory() as session, transaction(session):
        for object_id in ("visible", "hidden"):
            upsert_object(
                session,
                CatalogObjectIn(
                    id=object_id,
                    kind="service",
                    label=object_id.title(),
                    lifecycle="active",
                    health="healthy",
                    data={"schema_version": 1},
                ),
            )
        record_source_snapshot(
            session,
            _snapshot(
                _entry(
                    "visible",
                    fingerprint=visible_fp,
                    mappings=(_mapping("visible", visible_fp),),
                ),
                _entry("hidden", fingerprint=hidden_fp, mappings=(_mapping("hidden", hidden_fp),)),
                _entry(
                    "mixed",
                    fingerprint=mixed_fp,
                    mappings=(
                        _mapping("visible", mixed_fp),
                        _mapping("hidden", mixed_fp, role="derived"),
                    ),
                ),
                _entry("gap"),
            ),
        )

    ordinary = _access("ordinary", {"visible"})
    other = _access("other", {"visible"})
    admin = _access("admin", {"visible", "hidden"}, admin=True)
    limited_admin = _access("limited-admin", {"visible"}, admin=True)
    with alembic_session_factory() as session:
        first = query_source_coverage_page(
            session,
            ordinary,
            limit=1,
            include_total=True,
        )
        second = query_source_coverage_page(
            session,
            ordinary,
            limit=1,
            cursor=first.next_cursor,
            include_total=True,
        )
        assert first.summary.total == first.total == second.total == 2
        assert [*first.items, *second.items][1].mappings[0].object_id == "visible"
        assert {item.entry_id for item in [*first.items, *second.items]} == {"mixed", "visible"}
        assert sum(first.summary.by_state.values()) == 2

        with pytest.raises(CoverageAuthorityDenied):
            query_source_coverage_page(session, ordinary, scope="all")
        elevated = query_source_coverage_page(session, admin, scope="all", include_total=True)
        assert elevated.summary.total == elevated.total == 4
        assert "unmapped_operational" in {item.state for item in elevated.items}
        limited_elevated = query_source_coverage_page(
            session,
            limited_admin,
            scope="all",
            include_total=True,
        )
        assert limited_elevated.summary.total == limited_elevated.total == 3
        assert "hidden" not in {
            mapping.object_id
            for item in limited_elevated.items
            for mapping in item.mappings
        }

        for changed in (
            {"cursor": first.next_cursor, "access": other},
            {"cursor": first.next_cursor, "access": ordinary, "classification": "research"},
            {"cursor": first.next_cursor, "access": ordinary, "limit": 2},
            {"cursor": first.next_cursor, "access": ordinary, "direction": "desc"},
        ):
            access = changed.pop("access")
            with pytest.raises(InvalidCursor):
                query_source_coverage_page(session, access, include_total=True, **changed)

    with alembic_session_factory() as session, transaction(session):
        snapshot = load_current_snapshot(session)
        assert snapshot is not None
        hidden_only_change = tuple(
            replace(
                entry,
                mappings=(
                    *entry.mappings,
                    _mapping("hidden", entry.entry_fingerprint, role="derived"),
                ),
            )
            if entry.entry_id == "visible"
            else entry
            for entry in snapshot.entries
        )
        record_source_snapshot(
            session,
            _snapshot(*hidden_only_change, collected_at=LATER),
        )

    with alembic_session_factory() as session:
        after_hidden_change = query_source_coverage_page(
            session,
            ordinary,
            limit=1,
            cursor=first.next_cursor,
            include_total=True,
        )
        assert [item.entry_id for item in after_hidden_change.items] == ["visible"]

    with alembic_session_factory() as session, transaction(session):
        snapshot = load_current_snapshot(session)
        assert snapshot is not None
        visible_change = tuple(
            replace(entry, entry_fingerprint=_fingerprint("visible-changed"))
            if entry.entry_id == "visible"
            else entry
            for entry in snapshot.entries
        )
        record_source_snapshot(
            session,
            _snapshot(*visible_change, collected_at="2026-08-11T12:00:00Z"),
        )

    with alembic_session_factory() as session, pytest.raises(InvalidCursor):
        query_source_coverage_page(
            session,
            ordinary,
            limit=1,
            cursor=first.next_cursor,
            include_total=True,
        )


def test_rest_projects_recorded_snapshot_without_workspace_io(
    alembic_session_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fp = _fingerprint("api")
    with alembic_session_factory() as session, transaction(session):
        upsert_object(
            session,
            CatalogObjectIn(
                id="api-object",
                kind="service",
                label="API object",
                lifecycle="active",
                health="healthy",
                data={"schema_version": 1},
            ),
        )
        record_source_snapshot(
            session,
            _snapshot(_entry("api", fingerprint=fp, mappings=(_mapping("api-object", fp),))),
        )

    app = create_app()

    def session_dependency():
        with alembic_session_factory() as session:
            yield session

    def access_dependency() -> ReadAccess:
        return _access("api-principal", {"api-object"})

    app.dependency_overrides[get_session] = session_dependency
    app.dependency_overrides[require_api_read_access] = access_dependency
    monkeypatch.setattr(Path, "read_text", lambda *_args, **_kwargs: pytest.fail("workspace read"))
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/source-coverage",
            params={"include_total": "true", "target_kind": "service"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["total"] == payload["total"] == 1
    assert payload["items"][0]["state"] == "mapped_current"
    assert payload["items"][0]["mappings"][0]["target_kind"] == "service"
