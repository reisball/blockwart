from __future__ import annotations

import json

import pytest
import yaml
from pydantic import ValidationError
from sqlalchemy import func, select
from test_catalog_root_creation import root_client, root_state  # noqa: F401

from blockwart.cli import database as database_cli
from blockwart.db.session import transaction
from blockwart.domain.auth import Permission, PrincipalContext, PrincipalType
from blockwart.domain.object_schema import (
    BUILTIN_SCHEMAS,
    PROJECT_CATEGORY_VALUES,
    PROJECT_EVIDENCE_GRADE_VALUES,
    PROJECT_STATUS_VALUES,
)
from blockwart.domain.projects import (
    PROJECT_SOURCE_TYPE_VALUES,
    project_category_fields,
)
from blockwart.domain.schema_projection import kind_schema_projection
from blockwart.domain.search import SearchQuery
from blockwart.domain.ui_schema import ui_schema_payload
from blockwart.mcp.server import QUERY_FILTER_PROPERTIES, describe_schema_payload
from blockwart.models import AuditEvent, CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.agent import get_agent_object_context, search_agent_objects
from blockwart.services.audit import render_audit_summary_english
from blockwart.services.catalog import upsert_object
from blockwart.services.commands import (
    CommandNotFound,
    WriteContext,
    update_catalog_object,
)
from blockwart.services.policy import PolicySnapshot
from blockwart.services.project_migration import (
    ProjectMigrationError,
    apply_project_migration_plan,
    build_project_migration_plan,
    classify_legacy_project,
    project_data_sha256,
)
from blockwart.services.read_access import ReadAccess
from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME

RESEARCH_SOURCE = {
    "id": "rfc-9110",
    "source_type": "original",
    "title": "HTTP Semantics",
    "url": "https://www.rfc-editor.example/rfc9110",
    "author": "R. Fielding",
    "publisher": "RFC Editor",
    "published_at": "2026-01-05T00:00:00Z",
    "retrieved_at": "2026-05-02T09:30:00Z",
}


def _project(object_id: str, category: str = "implementation", **data) -> CatalogObjectIn:
    payload = {
        "schema_version": 1,
        "category": category,
        "project_status": "planned",
        **data,
    }
    return CatalogObjectIn(
        id=object_id,
        kind="project",
        label=object_id.replace("-", " ").title(),
        data=payload,
    )


def _asset(object_id: str) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind="system",
        label=object_id,
        data={"schema_version": 1},
    )


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


# --------------------------------------------------------------------------
# Canonical schema, projection, and boundary parity
# --------------------------------------------------------------------------


def test_canonical_project_schema_is_closed_and_projected_once() -> None:
    projection = kind_schema_projection("project")
    fields = {field["path"]: field for field in projection["data"]["fields"]}

    assert set(fields["category"]["enum"]) == set(PROJECT_CATEGORY_VALUES)
    assert fields["category"]["requirement"] == "required"
    assert set(fields["project_status"]["enum"]) == set(PROJECT_STATUS_VALUES)
    assert fields["project_status"]["requirement"] == "required"
    assert fields["related_assets[]"]["reference_kinds"] == [
        "device",
        "host",
        "network",
        "service",
        "system",
    ]
    assert fields["related_runbooks[]"]["reference_kinds"] == ["runbook"]
    assert fields["related_decisions[]"]["reference_kinds"] == ["decision"]
    assert fields["related_projects[]"]["reference_kinds"] == ["project"]
    assert projection["kind_class"] == "knowledge"
    assert projection["project"]["category"]["guessed_during_compatibility"] is False
    assert projection["project"]["external_sources"]["live_fetch"] is False
    assert projection["project"]["external_sources"]["full_text_import"] is False
    assert projection["project"]["ownership"]["grants_access"] is False
    assert projection["project"]["evidence"]["contradictory_findings_allowed"] is True
    assert projection["project"]["evidence"]["grades"] == list(
        PROJECT_EVIDENCE_GRADE_VALUES
    )

    # One central definition feeds MCP describe_schema and the UI payload.
    assert describe_schema_payload("project")["kinds"] == [projection]
    assert ui_schema_payload()["project"]["object_schema"] == projection


def test_project_source_contract_extends_decision_sources_without_weakening_them() -> (
    None
):
    project_fields = {field.path: field for field in BUILTIN_SCHEMAS["project"].fields}
    decision_fields = {field.path: field for field in BUILTIN_SCHEMAS["decision"].fields}

    # The shared base entry shape is identical on both kinds.
    for shared in ("source_type", "title", "url", "published_at"):
        project_field = project_fields[f"sources[].{shared}"]
        decision_field = decision_fields[f"docs[].{shared}"]
        assert project_field.field_type == decision_field.field_type
        assert project_field.required_in_item == decision_field.required_in_item
        assert project_field.max_length == decision_field.max_length
        assert (
            project_field.forbid_url_credentials
            == decision_field.forbid_url_credentials
        )

    # #144 stays closed on exactly its four accepted keys.
    assert decision_fields["docs[]"].allowed_keys == frozenset(
        {"source_type", "title", "url", "published_at"}
    )
    # #145 additively declares only the extra provenance it genuinely needs.
    assert project_fields["sources[]"].allowed_keys == frozenset(
        {
            "id",
            "source_type",
            "title",
            "url",
            "published_at",
            "author",
            "publisher",
            "retrieved_at",
            "reference_kind",
        }
    )
    assert project_fields["sources[].reference_kind"].enum_values == frozenset(
        {"document", "repository", "issue", "pull_request", "commit", "deployment"}
    )
    assert set(PROJECT_SOURCE_TYPE_VALUES) == set(
        decision_fields["docs[].source_type"].enum_values
    )


def test_project_ui_fields_derive_from_the_canonical_schema() -> None:
    canonical = BUILTIN_SCHEMAS["project"]
    expected = {
        field.path
        for field in canonical.fields
        if "." not in field.path
        and "[]" not in field.path
        and field.path != "schema_version"
        and field.forbidden_message is None
    }
    payload = ui_schema_payload()["project"]
    declared = {
        field["storage_path"].removeprefix("data_json.")
        for field in payload["schema_fields"]
        if field["storage_path"].startswith("data_json.")
    }
    assert declared == expected

    # Kind-scoped definitions must not overwrite the accepted Decision labels.
    decision_labels = {
        field["key"]: field["label_key"]
        for field in ui_schema_payload()["decision"]["schema_fields"]
    }
    project_labels = {
        field["key"]: field["label_key"] for field in payload["schema_fields"]
    }
    for shared in ("review_after", "related_runbooks", "related_decisions"):
        assert decision_labels[shared] == f"decision.field.{shared}.label"
        assert project_labels[shared] == f"project.field.{shared}.label"


def test_every_project_filter_is_published_on_every_read_boundary() -> None:
    for name in ("project_category", "project_status", "related_object"):
        assert name in QUERY_FILTER_PROPERTIES
    assert set(QUERY_FILTER_PROPERTIES["project_category"]["enum"]) == set(
        PROJECT_CATEGORY_VALUES
    )
    assert set(QUERY_FILTER_PROPERTIES["project_status"]["enum"]) == set(
        PROJECT_STATUS_VALUES
    )


# --------------------------------------------------------------------------
# Category-conditioned fields and lifecycle invariants
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("category", "field_name"),
    [
        ("implementation", "findings"),
        ("implementation", "hypothesis"),
        ("other", "root_cause"),
        ("research", "hypothesis"),
        ("research", "migration_plan"),
        ("experiment", "research_questions"),
        ("experiment", "root_cause"),
        ("incident_review", "measurements"),
        ("migration", "findings"),
    ],
)
def test_foreign_category_fields_fail_with_field_accurate_errors(
    category: str,
    field_name: str,
) -> None:
    value = (
        []
        if field_name
        in {"findings", "measurements", "migration_plan", "research_questions"}
        else "x"
    )
    with pytest.raises(ValidationError) as error:
        _project("wrong-category", category, **{field_name: value})
    assert f"data.{field_name}" in str(error.value)
    assert f"not part of the {category} project contract" in str(error.value)


@pytest.mark.parametrize("category", PROJECT_CATEGORY_VALUES)
def test_every_category_admits_its_own_declared_fields(category: str) -> None:
    samples = {
        "research_questions": ["Which cache tier helps most?"],
        "hypotheses": ["A shared cache reduces tail latency."],
        "methodology": "Replayed one week of production traffic.",
        "findings": [
            {"id": "f1", "statement": "Tail latency dropped.", "evidence_grade": "observed"}
        ],
        "limitations": ["Only one workload was replayed."],
        "conclusions": ["A shared cache is worth piloting."],
        "hypothesis": "The new pool sustains 200 rps.",
        "setup": "Two nodes behind the existing balancer.",
        "expected_result": "No error-rate change.",
        "observed_result": "Error rate stayed flat.",
        "measurements": [{"name": "p99", "quantity": "184", "unit": "ms"}],
        "conclusion": "The hypothesis held.",
        "reproducibility_notes": "Replay script is in the linked runbook.",
        "incident_window": {
            "started_at": "2026-04-02T01:10:00Z",
            "ended_at": "2026-04-02T02:40:00Z",
        },
        "impact": "Uploads failed for ninety minutes.",
        "detection": "The synthetic upload probe alerted.",
        "timeline_reference": {"type": "object_comments"},
        "root_cause": "A stale connection pool was never recycled.",
        "contributing_factors": ["The pool had no health check."],
        "remediation": ["Recycled the pool."],
        "prevention": ["Added a pool health check."],
        "source_state": "Single-node PostgreSQL 14.",
        "target_state": "PostgreSQL 16 with streaming replication.",
        "migration_plan": ["Provision the replica."],
        "verification": ["Compare row counts."],
        "rollback": "Repoint the application at the old primary.",
        "outcome": "Completed inside the maintenance window.",
        "lessons_learned": ["Rehearse the cutover twice."],
    }
    admitted = project_category_fields(category)
    data = {name: samples[name] for name in admitted}
    payload = _project(f"{category}-record", category, **data)
    for name in admitted:
        assert name in payload.data


@pytest.mark.parametrize(
    ("status", "extra", "path", "message"),
    [
        ("active", {}, "data.started_at", "is required for active projects"),
        ("paused", {}, "data.started_at", "is required for paused projects"),
        (
            "completed",
            {"started_at": "2026-01-01T00:00:00Z"},
            "data.completed_at",
            "is required for completed projects",
        ),
        (
            "planned",
            {"started_at": "2026-01-01T00:00:00Z"},
            "data.started_at",
            "is not allowed for planned projects",
        ),
        (
            "active",
            {
                "started_at": "2026-01-01T00:00:00Z",
                "completed_at": "2026-02-01T00:00:00Z",
            },
            "data.completed_at",
            "is not allowed for active projects",
        ),
        (
            "archived",
            {"completed_at": "2026-02-01T00:00:00Z"},
            "data.started_at",
            "is required when data.completed_at is present",
        ),
        (
            "completed",
            {
                "started_at": "2026-03-01T00:00:00Z",
                "completed_at": "2026-02-01T00:00:00Z",
            },
            "data.completed_at",
            "must not be earlier",
        ),
        (
            "active",
            {
                "started_at": "2026-03-01T00:00:00Z",
                "review_after": "2026-02-01T00:00:00Z",
            },
            "data.review_after",
            "must not be earlier",
        ),
    ],
)
def test_lifecycle_and_time_contradictions_fail_closed(
    status: str,
    extra: dict[str, str],
    path: str,
    message: str,
) -> None:
    with pytest.raises(ValidationError) as error:
        _project("lifecycle", "implementation", project_status=status, **extra)
    rendered = str(error.value)
    assert path in rendered
    assert message in rendered


def test_incident_window_and_evidence_timestamps_are_ordered() -> None:
    with pytest.raises(ValidationError, match="data.incident_window.ended_at"):
        _project(
            "incomplete-window",
            "incident_review",
            incident_window={"started_at": "2026-04-02T01:10:00Z"},
        )
    with pytest.raises(ValidationError, match="data.incident_window.ended_at"):
        _project(
            "incident",
            "incident_review",
            incident_window={
                "started_at": "2026-04-02T03:00:00Z",
                "ended_at": "2026-04-02T01:00:00Z",
            },
        )
    with pytest.raises(ValidationError, match=r"data\.findings\[0\]\.verified_at"):
        _project(
            "research",
            "research",
            findings=[
                {
                    "id": "f1",
                    "statement": "Cache hit ratio rose.",
                    "evidence_grade": "observed",
                    "observed_at": "2026-05-02T10:00:00Z",
                    "verified_at": "2026-05-01T10:00:00Z",
                }
            ],
        )
    with pytest.raises(ValidationError, match=r"data\.sources\[0\]\.retrieved_at"):
        _project(
            "source-time",
            "research",
            sources=[
                {
                    **RESEARCH_SOURCE,
                    "published_at": "2026-05-03T00:00:00Z",
                    "retrieved_at": "2026-05-02T00:00:00Z",
                }
            ],
        )


def test_review_and_incident_completion_follow_their_inputs() -> None:
    with pytest.raises(ValidationError, match="data.review_after"):
        _project(
            "early-review",
            project_status="completed",
            started_at="2026-01-01T00:00:00Z",
            completed_at="2026-03-01T00:00:00Z",
            review_after="2026-02-01T00:00:00Z",
        )
    with pytest.raises(ValidationError, match="data.completed_at"):
        _project(
            "early-incident-review",
            "incident_review",
            project_status="completed",
            started_at="2026-01-01T00:00:00Z",
            completed_at="2026-02-01T00:00:00Z",
            incident_window={
                "started_at": "2026-01-15T00:00:00Z",
                "ended_at": "2026-02-02T00:00:00Z",
            },
        )


def test_project_timestamps_normalize_to_utc() -> None:
    payload = _project(
        "normalized",
        "implementation",
        project_status="completed",
        started_at="2026-01-05T11:00:00+02:00",
        completed_at="2026-03-01T17:00:00Z",
        objective="  Trimmed objective.  ",
    )
    assert payload.data["started_at"] == "2026-01-05T09:00:00Z"
    assert payload.data["objective"] == "Trimmed objective."

    with pytest.raises(ValidationError, match="RFC 3339 timestamp with a timezone"):
        _project("naive", "implementation", started_at="2026-01-05T11:00:00")


def test_project_is_knowledge_and_rejects_asset_state() -> None:
    with pytest.raises(ValidationError, match="only valid for asset kinds"):
        CatalogObjectIn(
            id="stateful",
            kind="project",
            label="Stateful",
            lifecycle="active",
            data={
                "schema_version": 1,
                "category": "implementation",
                "project_status": "planned",
            },
        )


# --------------------------------------------------------------------------
# Ownership, evidence, and source safety
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("managed_by", "path"),
    [
        ({"label": "Platform team"}, "data.managed_by.kind"),
        ({"kind": "principal"}, "data.managed_by.principal_id"),
        ({"kind": "team"}, "data.managed_by.label"),
        (
            {"kind": "principal", "principal_id": "svc-a", "label": "Platform"},
            "data.managed_by.label",
        ),
        (
            {"kind": "person", "label": "Ada", "principal_id": "svc-a"},
            "data.managed_by.principal_id",
        ),
        ({"kind": "principal", "principal_id": "svc-a", "team": "x"}, "data.managed_by.team"),
    ],
)
def test_owner_provenance_is_unambiguous(managed_by: dict, path: str) -> None:
    with pytest.raises(ValidationError) as error:
        _project("owned", "implementation", managed_by=managed_by)
    assert path in str(error.value)


def test_owner_provenance_accepts_both_shapes_without_implying_access() -> None:
    principal = _project(
        "owned-principal",
        managed_by={"kind": "principal", "principal_id": "svc-platform"},
    )
    team = _project("owned-team", managed_by={"kind": "team", "label": "Platform"})
    assert principal.data["managed_by"] == {
        "kind": "principal",
        "principal_id": "svc-platform",
    }
    assert team.data["managed_by"]["label"] == "Platform"
    # The published contract states plainly that this is provenance only.
    ownership = kind_schema_projection("project")["project"]["ownership"]
    assert ownership["grants_access"] is False
    assert ownership["resolved"] is False


@pytest.mark.parametrize(
    ("entry", "path"),
    [
        ({"source_type": "original", "title": "T"}, "data.sources[0].url"),
        (
            {"source_type": "original", "url": "https://example.invalid/a"},
            "data.sources[0].title",
        ),
        (
            {"title": "T", "url": "https://example.invalid/a"},
            "data.sources[0].source_type",
        ),
        (
            {
                "source_type": "invented",
                "title": "T",
                "url": "https://example.invalid/a",
            },
            "data.sources[0].source_type",
        ),
        (
            {"source_type": "original", "title": "T", "url": "javascript:alert(1)"},
            "data.sources[0].url",
        ),
        (
            {"source_type": "original", "title": "T", "url": "data:text/html,<b>x</b>"},
            "data.sources[0].url",
        ),
        (
            {
                "source_type": "original",
                "title": "T",
                "url": "https://user:pw@example.invalid/a",
            },
            "data.sources[0].url",
        ),
        (
            {
                "source_type": "original",
                "title": "T",
                "url": "https://example.invalid/a?token=abc",
            },
            "data.sources[0].url",
        ),
        (
            {
                "source_type": "original",
                "title": "T",
                "url": "https://example.invalid/a",
                "body": "the whole paper",
            },
            "data.sources[0].body",
        ),
    ],
)
def test_source_entries_fail_with_field_accurate_paths(entry: dict, path: str) -> None:
    with pytest.raises(ValidationError) as error:
        _project("sourced", "research", sources=[entry])
    assert path in str(error.value)


@pytest.mark.parametrize(
    "data",
    [
        {"objective": "x", "api_key": "abcd"},
        {"sources": [{"source_type": "original", "title": "T", "password": "x"}]},
        {"managed_by": {"kind": "team", "label": "T", "secret": "x"}},
        {"future_extension": {"nested": {"deeper": {"token": "x"}}}},
    ],
)
def test_secret_shaped_keys_are_rejected_at_every_depth(data: dict) -> None:
    with pytest.raises(ValidationError):
        _project("unsafe", "research", **data)


def test_evidence_ids_and_citations_stay_unambiguous() -> None:
    other = dict(RESEARCH_SOURCE, id="second")
    with pytest.raises(ValidationError, match=r"data\.sources\[1\]\.id"):
        _project(
            "dupe-sources",
            "research",
            sources=[RESEARCH_SOURCE, dict(RESEARCH_SOURCE)],
        )
    with pytest.raises(ValidationError, match=r"data\.findings\[1\]\.id"):
        _project(
            "dupe-findings",
            "research",
            findings=[
                {"id": "f1", "statement": "A", "evidence_grade": "inferred"},
                {"id": "f1", "statement": "B", "evidence_grade": "inferred"},
            ],
        )
    with pytest.raises(ValidationError, match=r"data\.findings\[0\]\.source_ids\[0\]"):
        _project(
            "unknown-citation",
            "research",
            sources=[RESEARCH_SOURCE],
            findings=[
                {
                    "id": "f1",
                    "statement": "A",
                    "evidence_grade": "source_backed",
                    "source_ids": ["missing"],
                }
            ],
        )
    with pytest.raises(ValidationError, match=r"data\.findings\[0\]\.source_ids\[1\]"):
        _project(
            "repeat-citation",
            "research",
            sources=[RESEARCH_SOURCE, other],
            findings=[
                {
                    "id": "f1",
                    "statement": "A",
                    "evidence_grade": "source_backed",
                    "source_ids": ["rfc-9110", "rfc-9110"],
                }
            ],
        )
    with pytest.raises(ValidationError, match=r"data\.findings\[0\]\.source_ids"):
        _project(
            "ungrounded",
            "research",
            sources=[RESEARCH_SOURCE],
            findings=[
                {"id": "f1", "statement": "A", "evidence_grade": "source_backed"}
            ],
        )
    with pytest.raises(ValidationError, match=r"data\.measurements\[1\]\.name"):
        _project(
            "dupe-measurements",
            "experiment",
            measurements=[
                {"name": "p99", "quantity": "180", "observed_at": "2026-05-01T00:00:00Z"},
                {"name": "p99", "quantity": "190", "observed_at": "2026-05-01T00:00:00Z"},
            ],
        )


def test_contradictory_findings_remain_representable_and_distinct() -> None:
    payload = _project(
        "contradictions",
        "research",
        sources=[RESEARCH_SOURCE, dict(RESEARCH_SOURCE, id="bench-2026")],
        findings=[
            {
                "id": "cache-helps",
                "statement": "The shared cache lowers p99 latency.",
                "evidence_grade": "source_backed",
                "source_ids": ["rfc-9110"],
                "observed_at": "2026-05-02T10:00:00Z",
                "verified_at": "2026-05-09T10:00:00Z",
            },
            {
                "id": "cache-hurts",
                "statement": "The shared cache raises p99 latency under write bursts.",
                "evidence_grade": "observed",
                "source_ids": ["bench-2026"],
                "observed_at": "2026-05-04T10:00:00Z",
            },
        ],
        limitations=["Only two workloads were measured."],
        conclusions=["The cache helps read-heavy workloads only."],
        lessons_learned=["Measure write bursts before generalizing."],
    )
    findings = payload.data["findings"]
    assert [item["id"] for item in findings] == ["cache-helps", "cache-hurts"]
    assert findings[0]["evidence_grade"] != findings[1]["evidence_grade"]
    # Evidence timestamps stay separate from the generic object updated_at.
    assert "updated_at" not in findings[0]
    assert findings[0]["verified_at"] == "2026-05-09T10:00:00Z"


def test_timeline_reference_points_at_comments_or_one_declared_source() -> None:
    comments = _project(
        "timeline-comments",
        "incident_review",
        timeline_reference={"type": "object_comments", "note": "See the timeline."},
    )
    assert comments.data["timeline_reference"]["type"] == "object_comments"

    with pytest.raises(
        ValidationError,
        match=r"data\.timeline_reference\.source_id",
    ):
        _project(
            "timeline-conflict",
            "incident_review",
            timeline_reference={"type": "object_comments", "source_id": "x"},
        )
    with pytest.raises(
        ValidationError,
        match=r"data\.timeline_reference\.source_id",
    ):
        _project(
            "timeline-unknown",
            "incident_review",
            sources=[RESEARCH_SOURCE],
            timeline_reference={"type": "source", "source_id": "missing"},
        )
    resolved = _project(
        "timeline-source",
        "incident_review",
        sources=[RESEARCH_SOURCE],
        timeline_reference={"type": "source", "source_id": "rfc-9110"},
    )
    assert resolved.data["timeline_reference"]["source_id"] == "rfc-9110"


# --------------------------------------------------------------------------
# Persistence, no-op, audit, and comment separation
# --------------------------------------------------------------------------


def test_semantic_noop_keeps_revision_and_audit_stable(alembic_session_factory) -> None:
    payload = _project(
        "cache-rollout",
        "implementation",
        project_status="active",
        started_at="2026-01-05T11:00:00+02:00",
        objective="  Roll out the shared cache.  ",
    )
    with alembic_session_factory() as session:
        with transaction(session):
            created = upsert_object(session, payload)
            repeated = upsert_object(
                session,
                _project(
                    "cache-rollout",
                    "implementation",
                    project_status="active",
                    started_at="2026-01-05T09:00:00Z",
                    objective="Roll out the shared cache.",
                ),
                expected_revision=created.revision,
            )
            assert repeated.revision == created.revision == 1
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(AuditEvent)
                    .where(AuditEvent.object_id == "cache-rollout")
                )
                == 1
            )


def test_project_normalize_audit_summary_is_localized_and_body_free() -> None:
    summary = render_audit_summary_english(
        "project_normalize",
        {"object_ref": "project:cache-rollout"},
        legacy_summary="project_normalize",
    )
    assert summary == "Normalized Project contract for project:cache-rollout"


# --------------------------------------------------------------------------
# Authorization, concealment, and filters
# --------------------------------------------------------------------------


def test_authorized_context_and_filters_conceal_reference_targets(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _asset("visible-asset"))
            upsert_object(session, _asset("concealed-asset"))
            upsert_object(
                session,
                _project(
                    "scoped-project",
                    "research",
                    related_assets=["system:visible-asset", "system:concealed-asset"],
                    sources=[RESEARCH_SOURCE],
                    findings=[
                        {
                            "id": "f1",
                            "statement": "Concealed detail.",
                            "evidence_grade": "source_backed",
                            "source_ids": ["rfc-9110"],
                        }
                    ],
                ),
            )
        access = _reader(
            {
                "scoped-project": frozenset({Permission.DISCOVER, Permission.READ}),
                "visible-asset": frozenset({Permission.DISCOVER}),
            }
        )
        context = get_agent_object_context(session, "scoped-project", access)
        assert context is not None and context.visibility == "detail"
        assert context.data["related_assets"] == ["system:visible-asset"]

        assert [
            item.id
            for item in search_agent_objects(
                session,
                access,
                search=SearchQuery(
                    project_category="research",
                    related_object="system:visible-asset",
                ),
            )
        ] == ["scoped-project"]
        # A concealed target is never turned into an existence oracle.
        assert (
            search_agent_objects(
                session,
                access,
                search=SearchQuery(related_object="system:concealed-asset"),
            )
            == []
        )
        assert search_agent_objects(
            session, access, search=SearchQuery(query="concealed-asset")
        ) == []


def test_discover_only_stubs_never_expose_category_status_or_evidence(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(
                session,
                _project(
                    "secret-research",
                    "research",
                    project_status="active",
                    started_at="2026-01-01T00:00:00Z",
                    sources=[RESEARCH_SOURCE],
                    findings=[
                        {
                            "id": "f1",
                            "statement": "Sensitive conclusion.",
                            "evidence_grade": "observed",
                        }
                    ],
                    current_summary="Sensitive summary.",
                ),
            )
        access = _reader({"secret-research": frozenset({Permission.DISCOVER})})
        results = search_agent_objects(session, access)
        assert [item.id for item in results] == ["secret-research"]
        stub = results[0]
        assert stub.visibility == "stub"
        rendered = stub.model_dump_json()
        for leaked in (
            '"project_category":"research"',
            "Sensitive conclusion",
            "Sensitive summary",
            "rfc-9110",
            '"project_status":"active"',
        ):
            assert leaked not in rendered
        assert getattr(stub, "project_category", None) is None

        # Attribute filters require detail visibility, so a stub never matches.
        assert search_agent_objects(
            session, access, search=SearchQuery(project_category="research")
        ) == []
        assert search_agent_objects(
            session, access, search=SearchQuery(project_status="active")
        ) == []

        context = get_agent_object_context(session, "secret-research", access)
        assert context is not None and context.visibility == "stub"
        assert "Sensitive" not in context.model_dump_json()


def test_project_write_requires_read_access_to_every_reference(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _asset("target-asset"))
            upsert_object(session, _project("write-project"))
        context = WriteContext(
            principal=PrincipalContext(
                id="writer",
                principal_type=PrincipalType.SERVICE_ACCOUNT,
                login="writer",
                display_name="Writer",
            ),
            policy=PolicySnapshot(
                "writer",
                {"write-project": frozenset({Permission.WRITE})},
                {},
            ),
            channel="api",
        )
        for references in (
            {"related_assets": ["system:target-asset"]},
            {"related_assets": ["system:missing-asset"]},
            {"related_runbooks": ["runbook:target-asset"]},
        ):
            with pytest.raises(CommandNotFound):
                update_catalog_object(
                    session,
                    context,
                    object_id="write-project",
                    payload=_project("write-project", **references),
                    expected_revision=1,
                )


# --------------------------------------------------------------------------
# Legacy compatibility and the migration workflow
# --------------------------------------------------------------------------


def test_legacy_project_remains_readable_but_cannot_be_rewritten_free_form(
    alembic_session_factory,
) -> None:
    legacy = {"schema_version": 1, "notes": "Historical free-form project."}
    with alembic_session_factory() as session:
        session.add(
            CatalogObject(
                id="legacy-project",
                kind="project",
                label="Legacy project",
                status="active",
                data_json=json.dumps(legacy),
                provenance_json="{}",
                revision=1,
            )
        )
        session.commit()
        access = _reader(
            {"legacy-project": frozenset({Permission.DISCOVER, Permission.READ})}
        )
        context = get_agent_object_context(session, "legacy-project", access)
        assert context is not None
        assert context.data == legacy

    with pytest.raises(ValidationError, match="data.category"):
        CatalogObjectIn(
            id="legacy-project",
            kind="project",
            label="Legacy project",
            data=legacy,
        )


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ({"schema_version": 1}, {"missing_category", "missing_project_status"}),
        (
            {"category": "research", "project_status": "planned", "hypothesis": "x"},
            {"contradictory_category_fields"},
        ),
        (
            {"category": "invented", "project_status": "planned"},
            {"invalid_category"},
        ),
        (
            {"category": "research", "project_status": "invented"},
            {"invalid_project_status"},
        ),
        (
            {"hypothesis": "x", "root_cause": "y"},
            {"missing_category", "missing_project_status", "ambiguous_category"},
        ),
        (
            {
                "category": "research",
                "project_status": "planned",
                "sources": [{"url": "javascript:alert(1)"}],
            },
            {"invalid_sources"},
        ),
        (
            {
                "category": "research",
                "project_status": "planned",
                "findings": [{"statement": "x"}],
            },
            {"invalid_evidence"},
        ),
        (
            {"category": "implementation", "project_status": "active"},
            {"invalid_lifecycle"},
        ),
        (
            {
                "measurements": [
                    {"name": "p99", "quantity": "184", "unit": "ms"}
                ]
            },
            {"missing_category", "missing_project_status"},
        ),
    ],
)
def test_classification_reports_explicit_blockers_without_guessing(
    data: dict,
    expected: set[str],
) -> None:
    assert set(classify_legacy_project(data)) == expected


def test_migration_is_dry_run_first_and_apply_is_explicit(
    alembic_session_factory,
) -> None:
    before = {"schema_version": 1, "notes": "Keep this legacy note."}
    fingerprint = project_data_sha256(before)
    with alembic_session_factory() as session:
        session.add(
            CatalogObject(
                id="legacy-migration",
                kind="project",
                label="Legacy migration",
                status="active",
                data_json=json.dumps(before),
                provenance_json="{}",
                revision=3,
            )
        )
        session.commit()

        blocked = build_project_migration_plan(session)
        assert {item.code for item in blocked.diagnostics} == {
            "missing_category",
            "missing_project_status",
        }
        assert blocked.changes == ()
        with pytest.raises(ProjectMigrationError, match="has blockers"):
            apply_project_migration_plan(session, blocked)

        mapping = {
            "legacy-migration": {
                "expected_data_sha256": fingerprint,
                "data_patch": {
                    "category": "migration",
                    "project_status": "completed",
                    "started_at": "2026-01-05T09:00:00Z",
                    "completed_at": "2026-03-01T17:00:00Z",
                    "source_state": "PostgreSQL 14",
                    "target_state": "PostgreSQL 16",
                },
            }
        }
        plan = build_project_migration_plan(session, mapping)
        assert plan.diagnostics == ()
        assert len(plan.changes) == 1
        # Planning alone must never mutate storage.
        row = session.get(CatalogObject, "legacy-migration")
        assert json.loads(row.data_json) == before
        assert row.revision == 3

        with transaction(session):
            assert apply_project_migration_plan(session, plan) == 1
        session.expire_all()
        row = session.get(CatalogObject, "legacy-migration")
        stored = json.loads(row.data_json)
        assert stored["notes"] == "Keep this legacy note."
        assert stored["category"] == "migration"
        assert row.revision == 4
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == "project_normalize")
            )
            == 1
        )

        # A plan built against superseded data is rejected wholesale.
        with pytest.raises(ProjectMigrationError, match="changed after planning"):
            apply_project_migration_plan(session, plan)


def test_migration_rejects_stale_plans_and_is_all_or_nothing(
    alembic_session_factory,
) -> None:
    first = {"schema_version": 1, "notes": "first"}
    second = {"schema_version": 1, "notes": "second"}
    with alembic_session_factory() as session:
        for object_id, data in (("stale-a", first), ("stale-b", second)):
            session.add(
                CatalogObject(
                    id=object_id,
                    kind="project",
                    label=object_id,
                    status="active",
                    data_json=json.dumps(data),
                    provenance_json="{}",
                    revision=1,
                )
            )
        session.commit()
        patch = {"category": "other", "project_status": "planned"}
        plan = build_project_migration_plan(
            session,
            {
                "stale-a": {
                    "expected_data_sha256": project_data_sha256(first),
                    "data_patch": patch,
                },
                "stale-b": {
                    "expected_data_sha256": project_data_sha256(second),
                    "data_patch": patch,
                },
            },
        )
        assert len(plan.changes) == 2

        # Another writer changes one row between planning and applying.
        row = session.get(CatalogObject, "stale-b")
        row.data_json = json.dumps({"schema_version": 1, "notes": "changed"})
        session.commit()

        with pytest.raises(ProjectMigrationError, match="changed after planning"), (
            transaction(session)
        ):
            apply_project_migration_plan(session, plan)
        session.expire_all()
        assert json.loads(session.get(CatalogObject, "stale-a").data_json) == first
        assert session.get(CatalogObject, "stale-a").revision == 1


def test_migration_reports_fingerprint_and_unknown_mapping_blockers(
    alembic_session_factory,
) -> None:
    before = {"schema_version": 1, "notes": "n"}
    with alembic_session_factory() as session:
        session.add(
            CatalogObject(
                id="fingerprint-project",
                kind="project",
                label="Fingerprint",
                status="active",
                data_json=json.dumps(before),
                provenance_json="{}",
                revision=1,
            )
        )
        session.commit()
        plan = build_project_migration_plan(
            session,
            {
                "fingerprint-project": {
                    "expected_data_sha256": "0" * 64,
                    "data_patch": {"category": "other", "project_status": "planned"},
                },
                "absent-project": {
                    "expected_data_sha256": "1" * 64,
                    "data_patch": {"category": "other", "project_status": "planned"},
                },
            },
        )
        assert plan.diagnostic_counts == {
            "fingerprint_mismatch": 1,
            "unknown_mapping_object": 1,
        }


def test_migration_cli_dry_run_is_read_only_and_apply_is_separate(
    alembic_database_factory,
    tmp_path,
    capsys,
) -> None:
    database = alembic_database_factory("projects.sqlite3")
    before = {"schema_version": 1, "notes": "cli legacy"}
    with database.sessions() as session:
        session.add(
            CatalogObject(
                id="cli-project",
                kind="project",
                label="CLI project",
                status="active",
                data_json=json.dumps(before),
                provenance_json="{}",
                revision=1,
            )
        )
        session.commit()

    assert database_cli.main(["--database-url", database.database_url, "projects"]) == 1
    captured = capsys.readouterr()
    assert "database_projects_error" in captured.out
    assert "code=missing_category" in captured.err

    mapping_path = tmp_path / "projects.yaml"
    mapping_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "projects": [
                    {
                        "object_id": "cli-project",
                        "expected_data_sha256": project_data_sha256(before),
                        "data_patch": {
                            "category": "other",
                            "project_status": "planned",
                            "objective": "Keep the identifier stable.",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    arguments = [
        "--database-url",
        database.database_url,
        "--mapping",
        str(mapping_path),
        "projects",
    ]
    assert database_cli.main(arguments) == 0
    assert "mode=dry-run" in capsys.readouterr().out
    with database.sessions() as session:
        assert json.loads(session.get(CatalogObject, "cli-project").data_json) == before

    assert database_cli.main([*arguments, "--apply"]) == 0
    assert "mode=apply" in capsys.readouterr().out
    with database.sessions() as session:
        row = session.get(CatalogObject, "cli-project")
        stored = json.loads(row.data_json)
        assert stored["category"] == "other"
        assert stored["notes"] == "cli legacy"
        assert row.revision == 2


# --------------------------------------------------------------------------
# REST, Agent API, MCP, and UI parity
# --------------------------------------------------------------------------


def test_rest_agent_and_mcp_share_project_filters(root_client, root_state) -> None:  # noqa: F811
    headers = {"Authorization": f"Bearer {root_state['owner_token']}"}
    query = {
        "project_category": "research",
        "project_status": "planned",
        "related_object": "system:example",
    }
    for path in (
        "/api/v1/objects",
        "/api/v1/context",
        "/api/agent/search",
        "/api/agent/context",
    ):
        response = root_client.get(path, headers=headers, params=query)
        assert response.status_code == 200, response.text

    for path in ("/api/v1/objects", "/api/agent/search"):
        rejected = root_client.get(
            path,
            headers=headers,
            params={"related_object": "unsupported:x"},
        )
        assert rejected.status_code == 422, rejected.text


def test_rest_and_ui_write_canonical_projects(root_client, root_state) -> None:  # noqa: F811
    headers = {
        "Authorization": f"Bearer {root_state['owner_token']}",
        "Idempotency-Key": "project-rest-0001",
    }
    api_response = root_client.post(
        "/api/v1/roots",
        headers=headers,
        json={
            "id": "cache-research",
            "kind": "project",
            "label": "Shared cache research",
            "data": {
                "schema_version": 1,
                "category": "research",
                "project_status": "planned",
                "objective": "Decide whether a shared cache is worth piloting.",
                "sources": [RESEARCH_SOURCE],
                "findings": [
                    {
                        "id": "f1",
                        "statement": "Read-heavy paths benefit most.",
                        "evidence_grade": "source_backed",
                        "source_ids": ["rfc-9110"],
                        "observed_at": "2026-05-02T10:00:00Z",
                    }
                ],
            },
        },
    )
    assert api_response.status_code == 201, api_response.text

    invalid = root_client.post(
        "/api/v1/roots",
        headers={
            "Authorization": f"Bearer {root_state['owner_token']}",
            "Idempotency-Key": "project-rest-0002",
        },
        json={
            "id": "invalid-project",
            "kind": "project",
            "label": "Invalid project",
            "data": {
                "schema_version": 1,
                "category": "research",
                "project_status": "planned",
                "hypothesis": "belongs to experiment",
            },
        },
    )
    assert invalid.status_code == 422
    detail = invalid.json()["error"]["details"][0]
    assert detail["path"] == "data.hypothesis"
    assert detail["code"] == "field_not_allowed"
    assert detail["rule"] == "reject_project_contradictory_fields"

    root_client.cookies.set(AUTH_SESSION_COOKIE_NAME, root_state["owner_session"].value)
    root_client.cookies.set(
        AUTH_CSRF_COOKIE_NAME,
        root_state["owner_session"].csrf_token,
    )
    ui_response = root_client.post(
        "/roots",
        data={
            "csrf_token": root_state["owner_session"].csrf_token,
            "object_id": "cutover-review",
            "kind": "project",
            "primary_name": "Database cutover review",
            "status": "active",
            "summary": "",
            "category": "incident_review",
            "project_status": "completed",
            "started_at": "2026-04-02T01:00:00Z",
            "completed_at": "2026-04-09T12:00:00Z",
            "objective": "Understand the failed cutover.",
            "idempotency_key": "project-ui-create-0001",
        },
        follow_redirects=False,
    )
    assert ui_response.status_code == 303, ui_response.text

    with root_state["session_factory"]() as session:
        stored = json.loads(session.get(CatalogObject, "cutover-review").data_json)
        assert stored["category"] == "incident_review"
        assert stored["project_status"] == "completed"
        assert stored["started_at"] == "2026-04-02T01:00:00Z"


def test_structured_ui_editor_round_trips_without_raw_json(
    root_client,  # noqa: F811
    root_state,  # noqa: F811
) -> None:
    headers = {
        "Authorization": f"Bearer {root_state['owner_token']}",
        "Idempotency-Key": "project-ui-editor-0001",
    }
    created = root_client.post(
        "/api/v1/roots",
        headers=headers,
        json={
            "id": "cache-study",
            "kind": "project",
            "label": "Cache study",
            "data": {
                "schema_version": 1,
                "category": "research",
                "project_status": "planned",
                "legacy_extension": {"kept": True},
            },
        },
    )
    assert created.status_code == 201, created.text
    etag = created.headers["ETag"]

    root_client.cookies.set(AUTH_SESSION_COOKIE_NAME, root_state["owner_session"].value)
    root_client.cookies.set(
        AUTH_CSRF_COOKIE_NAME,
        root_state["owner_session"].csrf_token,
    )
    editor = root_client.get("/objects/cache-study?edit=project")
    assert editor.status_code == 200
    assert 'name="research_questions"' in editor.text
    assert 'name="finding_evidence_grade"' in editor.text
    assert 'name="source_url"' in editor.text
    # Experiment-only controls stay out of a research editor.
    assert 'name="measurement_quantity"' not in editor.text

    saved = root_client.post(
        "/objects/cache-study",
        data={
            "csrf_token": root_state["owner_session"].csrf_token,
            "if_match": etag,
            "category": "research",
            "project_status": "active",
            "started_at": "2026-05-01T09:00:00Z",
            "objective": "Decide on a shared cache.",
            "in_scope": "Read-heavy API paths",
            "out_of_scope": "Write-heavy batch jobs",
            "research_questions": "Does a shared cache lower p99?",
            "hypotheses": "It lowers p99 for reads.",
            "methodology": "Replayed one week of traffic.",
            "conclusions": "Pilot it for reads.",
            "lessons_learned": "Measure write bursts too.",
            "source_id": "rfc-9110",
            "source_source_type": "original",
            "source_title": "HTTP Semantics",
            "source_url": "https://www.rfc-editor.example/rfc9110",
            "source_author": "R. Fielding",
            "finding_id": "f1",
            "finding_statement": "Read paths improved.",
            "finding_evidence_grade": "source_backed",
            "finding_source_ids": "rfc-9110",
            "finding_observed_at": "2026-05-02T10:00:00Z",
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303, saved.text

    with root_state["session_factory"]() as session:
        stored = json.loads(session.get(CatalogObject, "cache-study").data_json)
    assert stored["research_questions"] == ["Does a shared cache lower p99?"]
    assert stored["sources"][0]["author"] == "R. Fielding"
    assert stored["findings"][0]["source_ids"] == ["rfc-9110"]
    # Unknown legacy extension data survives a structured UI edit untouched.
    assert stored["legacy_extension"] == {"kept": True}

    detail = root_client.get("/objects/cache-study")
    assert detail.status_code == 200
    assert "Research questions" in detail.text
    assert "Source-backed" in detail.text
    assert "project.field." not in detail.text
    assert "project.section." not in detail.text


def test_ui_never_renders_unsafe_legacy_source_values(
    root_client,  # noqa: F811
    root_state,  # noqa: F811
) -> None:
    with root_state["session_factory"]() as session:
        session.add(
            CatalogObject(
                id="legacy-sources",
                kind="project",
                label="Legacy sources",
                status="active",
                data_json=json.dumps(
                    {
                        "schema_version": 1,
                        "sources": [
                            {"url": "javascript:alert(1)", "title": "Unsafe"},
                            "https://plain.example.invalid/legacy",
                        ],
                    }
                ),
                provenance_json="{}",
                revision=1,
            )
        )
        session.commit()

    root_client.cookies.set(AUTH_SESSION_COOKIE_NAME, root_state["owner_session"].value)
    response = root_client.get("/objects/legacy-sources")
    assert response.status_code == 200
    assert "javascript:alert(1)" not in response.text
    assert "Legacy" in response.text

    with root_state["session_factory"]() as session:
        stored = json.loads(session.get(CatalogObject, "legacy-sources").data_json)
    # Nothing was silently discarded from storage.
    assert stored["sources"][0]["url"] == "javascript:alert(1)"


def test_ui_preserves_concealed_references_on_structured_edit(
    alembic_session_factory,
) -> None:
    from blockwart.ui.project_forms import ProjectForm, apply_project_form_data
    from blockwart.ui.routes import _concealed_project_references

    stored = {
        "schema_version": 1,
        "category": "implementation",
        "project_status": "planned",
        "related_assets": ["system:visible-asset", "system:concealed-asset"],
    }
    access = _reader({"visible-asset": frozenset({Permission.DISCOVER})})
    concealed = _concealed_project_references(stored, access)
    assert concealed == {"related_assets": ["system:concealed-asset"]}

    form = ProjectForm(
        category="implementation",
        project_status="planned",
        related_assets="system:visible-asset",
    )
    data = dict(stored)
    apply_project_form_data(data, form, concealed_references=concealed)
    assert data["related_assets"] == [
        "system:visible-asset",
        "system:concealed-asset",
    ]


def test_switching_category_clears_the_previous_category_fields() -> None:
    from blockwart.ui.project_forms import ProjectForm, apply_project_form_data

    data = {
        "schema_version": 1,
        "category": "research",
        "project_status": "planned",
        "research_questions": ["Old question"],
        "findings": [{"id": "f1", "statement": "Old", "evidence_grade": "inferred"}],
        "legacy_extension": {"kept": True},
    }
    form = ProjectForm(
        category="experiment",
        project_status="planned",
        hypothesis="The new pool sustains 200 rps.",
    )
    apply_project_form_data(data, form)
    assert "research_questions" not in data
    assert "findings" not in data
    assert data["hypothesis"] == "The new pool sustains 200 rps."
    assert data["legacy_extension"] == {"kept": True}
    # The result satisfies the canonical contract with no leftovers.
    CatalogObjectIn(id="switched", kind="project", label="Switched", data=data)


def test_project_comments_stay_separate_from_canonical_fields(
    root_client,  # noqa: F811
    root_state,  # noqa: F811
) -> None:
    headers = {
        "Authorization": f"Bearer {root_state['owner_token']}",
        "Idempotency-Key": "project-comment-0001",
    }
    created = root_client.post(
        "/api/v1/roots",
        headers=headers,
        json={
            "id": "comment-project",
            "kind": "project",
            "label": "Comment project",
            "data": {
                "schema_version": 1,
                "category": "implementation",
                "project_status": "planned",
                "current_summary": "Reviewed result.",
            },
        },
    )
    assert created.status_code == 201, created.text

    comment = root_client.post(
        "/api/v1/objects/comment-project/comments",
        headers={
            "Authorization": f"Bearer {root_state['owner_token']}",
            "Idempotency-Key": "project-comment-0002",
        },
        json={"body": "Work note: rerun the benchmark next week."},
    )
    assert comment.status_code == 201, comment.text

    with root_state["session_factory"]() as session:
        stored = json.loads(session.get(CatalogObject, "comment-project").data_json)
        events = session.scalars(
            select(AuditEvent).where(AuditEvent.object_id == "comment-project")
        ).all()
    # A comment never becomes a finding, recommendation, or status change.
    assert stored["current_summary"] == "Reviewed result."
    assert "findings" not in stored
    assert "recommendations" not in stored
    assert stored["project_status"] == "planned"
    for event in events:
        assert "rerun the benchmark" not in (event.details_json or "")


def test_project_kind_is_registered_in_every_read_boundary() -> None:
    from blockwart.services.queries import UI_VISIBLE_KINDS

    assert "project" in UI_VISIBLE_KINDS
    assert "project" in QUERY_FILTER_PROPERTIES["kind"]["enum"]
