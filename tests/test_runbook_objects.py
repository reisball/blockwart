from __future__ import annotations

import json
import re
from collections.abc import Generator
from html import unescape
from pathlib import Path

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from test_catalog_root_creation import root_client, root_state  # noqa: F401

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import Permission, PrincipalContext, PrincipalType
from blockwart.domain.object_schema import (
    BUILTIN_SCHEMAS,
    RUNBOOK_STATUS_VALUES,
)
from blockwart.domain.runbooks import RUNBOOK_RISKS, RunbookIntegrityError
from blockwart.domain.schema_projection import kind_schema_projection
from blockwart.domain.search import SearchQuery
from blockwart.domain.ui_schema import ui_schema_payload
from blockwart.main import create_app
from blockwart.mcp.server import QUERY_FILTER_PROPERTIES, describe_schema_payload
from blockwart.models import AuditEvent, CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.agent import get_agent_object_context, search_agent_objects
from blockwart.services.catalog import upsert_object
from blockwart.services.commands import CommandNotFound, WriteContext, update_catalog_object
from blockwart.services.policy import PolicySnapshot
from blockwart.services.read_access import ReadAccess
from blockwart.services.runbook_migration import (
    RunbookMigrationError,
    apply_runbook_migration_plan,
    build_runbook_migration_plan,
    classify_legacy_runbook,
    runbook_data_sha256,
)
from blockwart.ui.runbook_forms import RunbookForm, apply_runbook_form_data
from blockwart.ui.security import (
    AUTH_CSRF_COOKIE_NAME,
    AUTH_SESSION_COOKIE_NAME,
    require_browser_read_access,
)


def _runbook(object_id: str, **data) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind="runbook",
        label=object_id.replace("-", " ").title(),
        data={
            "schema_version": 1,
            "runbook_status": "draft",
            "approval_required": False,
            **data,
        },
    )


def _active_runbook(object_id: str, **data) -> CatalogObjectIn:
    canonical = {
        "runbook_status": "active",
        "purpose": "Restore a reviewed healthy operating state.",
        "risk_level": "read-only",
        "prerequisites": [
            {"id": "access", "description": "Obtain approved console access."}
        ],
        "steps": [
            {
                "id": "inspect",
                "description": "Inspect the fictitious service status.",
                "command": "printf 'status only\\n'\n",
                "expected_effect": "The local status is displayed without a change.",
            }
        ],
        "verification": [
            {
                "id": "healthy",
                "description": "Review the reported health.",
                "success_expectation": "The fictitious service reports healthy.",
            }
        ],
        "last_verified_at": "2026-08-12T12:00:00Z",
        **data,
    }
    return _runbook(object_id, **canonical)


def _asset(object_id: str, kind: str = "system") -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind=kind,
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


def test_runbook_schema_is_canonical_and_shared_by_all_schema_surfaces() -> None:
    projection = kind_schema_projection("runbook")
    fields = {field["path"]: field for field in projection["data"]["fields"]}

    assert set(fields["runbook_status"]["enum"]) == set(RUNBOOK_STATUS_VALUES)
    assert fields["runbook_status"]["requirement"] == "required"
    assert set(fields["risk_level"]["enum"]) == set(RUNBOOK_RISKS)
    assert fields["steps[]"]["additional_properties"] is False
    assert fields["steps[].id"]["requirement"] == "required"
    assert "strip_whitespace" not in fields["steps[].command"]
    assert fields["steps[].expected_effect"]["requirement"] == "required"
    assert fields["verification[].success_expectation"]["requirement"] == "required"
    assert fields["applies_to[]"]["reference_kinds"] == [
        "device",
        "host",
        "network",
        "service",
        "system",
    ]
    assert fields["credential_references[]"]["reference_kinds"] == [
        "credential_reference"
    ]
    assert projection["runbook"]["commands"]["inert"] is True
    assert projection["runbook"]["commands"]["shell_execution"] is False
    assert projection["runbook"]["procedures"]["distinct"] is True
    assert projection["kind_class"] == "knowledge"
    assert describe_schema_payload("runbook")["kinds"] == [projection]
    assert ui_schema_payload()["runbook"]["object_schema"] == projection


def test_runbook_filters_are_published_for_rest_agent_and_mcp_contracts() -> None:
    for name in ("runbook_status", "runbook_risk", "related_object"):
        assert name in QUERY_FILTER_PROPERTIES
    assert QUERY_FILTER_PROPERTIES["runbook_status"]["enum"] == list(
        RUNBOOK_STATUS_VALUES
    )
    assert set(QUERY_FILTER_PROPERTIES["runbook_risk"]["enum"]) == set(
        RUNBOOK_RISKS
    )


@pytest.mark.parametrize("status", RUNBOOK_STATUS_VALUES)
def test_runbook_status_vocabulary_is_closed(status: str) -> None:
    fields: dict[str, object] = {"runbook_status": status}
    if status == "deprecated":
        fields["deprecation_rationale"] = "Replaced by a reviewed procedure."
    if status == "superseded":
        fields["superseded_by"] = "runbook:successor"
    payload = (
        _active_runbook("status-contract", **fields)
        if status in {"approved", "active"}
        else _runbook("status-contract", **fields)
    )
    assert payload.data["runbook_status"] == status


def test_approved_and_active_runbooks_require_complete_reviewed_truth() -> None:
    required = {
        "purpose": "Diagnose the fictitious service.",
        "risk_level": "read-only",
        "prerequisites": [{"id": "access", "description": "Read access exists."}],
        "steps": [
            {
                "id": "inspect",
                "title": "Inspect state",
                "expected_effect": "No state changes.",
            }
        ],
        "verification": [
            {
                "id": "check",
                "description": "Read the result.",
                "success_expectation": "A healthy result is visible.",
            }
        ],
        "last_verified_at": "2026-08-12T12:00:00Z",
    }
    for status in ("approved", "active"):
        assert _runbook("complete", runbook_status=status, **required).data
        for field in required:
            incomplete = dict(required)
            incomplete.pop(field)
            with pytest.raises(ValidationError, match=field):
                _runbook("incomplete", runbook_status=status, **incomplete)


def test_change_approval_rollback_and_recovery_rules_are_distinct() -> None:
    rollback = [
        {
            "id": "undo",
            "description": "Restore the previous configuration.",
            "expected_effect": "The previous configuration is active.",
        }
    ]
    recovery = [
        {
            "id": "recover",
            "description": "Restore the fictitious database backup.",
            "expected_effect": "The database returns to a healthy state.",
        }
    ]
    change = _runbook(
        "change",
        risk_level="disruptive",
        approval_required=True,
        approval_requirement="Two-person approval recorded outside Blockwart.",
        change_fallback="rollback",
        rollback=rollback,
    )
    assert change.data["rollback"] != change.data.get("recovery")
    with pytest.raises(ValidationError, match="approval_required"):
        _runbook("unsafe-change", risk_level="destructive")
    with pytest.raises(ValidationError, match="rollback.*recovery"):
        _runbook(
            "missing-procedure",
            risk_level="disruptive",
            approval_required=True,
            approval_requirement="Reviewed approval is required.",
            change_fallback="rollback",
        )
    assert _runbook(
        "recovery-change",
        risk_level="safe-change",
        change_fallback="recovery",
        change_fallback_rationale="Reversal cannot repair partially written data.",
        recovery=recovery,
    ).data["change_fallback"] == "recovery"
    assert _runbook(
        "no-rollback-change",
        risk_level="safe-change",
        change_fallback="no_rollback",
        change_fallback_rationale="The read model is rebuilt from its source.",
    ).data["change_fallback"] == "no_rollback"


def test_lifecycle_rationale_successor_and_timestamp_rules_fail_closed() -> None:
    with pytest.raises(ValidationError, match="deprecation_rationale"):
        _runbook("deprecated", runbook_status="deprecated")
    with pytest.raises(ValidationError, match="superseded_by"):
        _runbook("superseded", runbook_status="superseded")
    with pytest.raises(ValidationError, match="review_after"):
        _runbook(
            "time-order",
            last_verified_at="2026-08-12T12:00:00Z",
            review_after="2026-08-11T12:00:00Z",
        )
    with pytest.raises(ValidationError, match="only valid for asset kinds"):
        CatalogObjectIn(
            id="asset-state",
            kind="runbook",
            label="Asset state",
            lifecycle="active",
            data={"runbook_status": "draft", "approval_required": False},
        )


def test_instruction_ids_shapes_and_nested_secrets_are_rejected() -> None:
    with pytest.raises(ValidationError, match="repeats an earlier entry id"):
        _runbook(
            "duplicate",
            steps=[
                {"id": "same", "title": "One", "expected_effect": "One."},
                {"id": "same", "title": "Two", "expected_effect": "Two."},
            ],
        )
    with pytest.raises(ValidationError, match="description.*title"):
        _runbook(
            "blank",
            steps=[{"id": "blank", "command": "true", "expected_effect": "None."}],
        )
    for unsafe in (
        {
            "steps": [
                {
                    "id": "s",
                    "title": "X",
                    "command": "Bearer abcdefghijklmnopqrstuvwxyz",
                    "expected_effect": "X",
                }
            ]
        },
        {
            "steps": [
                {
                    "id": "s",
                    "title": "X",
                    "expected_effect": "X",
                    "password": "nested",
                }
            ]
        },
        {"credential_values": [{"value": "must-never-be-stored"}]},
    ):
        with pytest.raises(ValidationError):
            _runbook("unsafe", **unsafe)


def test_commands_round_trip_byte_for_byte_and_browser_form_does_not_expand() -> None:
    command = "  printf '%s\\n' '${UNCHANGED}'  \r\nnext-line\n"
    payload = _active_runbook("exact-command")
    payload.data["steps"][0]["command"] = command
    validated = CatalogObjectIn.model_validate(payload.model_dump())
    assert validated.data["steps"][0]["command"].encode() == command.encode()

    form = RunbookForm(
        runbook_status="draft",
        approval_required="false",
        step_id=["s1"],
        step_title=["Inert instruction"],
        step_command=[command],
        step_expected_effect=["No execution occurs."],
    )
    data: dict = {}
    apply_runbook_form_data(data, form)
    assert data["steps"][0]["command"].encode() == command.encode()


def test_supersession_self_reference_and_cycles_are_atomic(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _runbook("first"))
            upsert_object(session, _runbook("second", supersedes=["runbook:first"]))
        with pytest.raises(RunbookIntegrityError):
            with transaction(session):
                upsert_object(
                    session,
                    _runbook("first", supersedes=["runbook:first"]),
                    expected_revision=1,
                )
        assert session.get(CatalogObject, "first").revision == 1
        with pytest.raises(RunbookIntegrityError):
            with transaction(session):
                upsert_object(
                    session,
                    _runbook("first", supersedes=["runbook:second"]),
                    expected_revision=1,
                )
        assert session.get(CatalogObject, "first").revision == 1


def test_reference_writes_require_readable_existing_kind_correct_targets(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _asset("target"))
            upsert_object(session, _runbook("writer-runbook"))
        context = WriteContext(
            principal=PrincipalContext(
                id="writer",
                principal_type=PrincipalType.SERVICE_ACCOUNT,
                login="writer",
                display_name="Writer",
            ),
            policy=PolicySnapshot(
                "writer",
                {
                    "writer-runbook": frozenset(
                        {Permission.DISCOVER, Permission.WRITE}
                    )
                },
                {},
            ),
            channel="api",
        )
        for reference in ("system:target", "system:missing", "service:target"):
            with pytest.raises(CommandNotFound, match="runbook reference target not found"):
                update_catalog_object(
                    session,
                    context,
                    object_id="writer-runbook",
                    payload=_runbook("writer-runbook", applies_to=[reference]),
                    expected_revision=1,
                )


def test_filters_and_stubs_do_not_leak_runbook_contract_fields(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _asset("visible-target"))
            upsert_object(session, _asset("concealed-target"))
            upsert_object(
                session,
                _active_runbook(
                    "private-runbook",
                    risk_level="read-only",
                    applies_to=["system:visible-target", "system:concealed-target"],
                    credential_references=[],
                    sources=[
                        {
                            "id": "docs",
                            "source_type": "documentation",
                            "title": "Fictitious operating guide",
                            "url": "https://docs.example.invalid/runbook",
                        }
                    ],
                ),
            )
        detail_access = _reader(
            {
                "private-runbook": frozenset({Permission.DISCOVER, Permission.READ}),
                "visible-target": frozenset({Permission.DISCOVER}),
            }
        )
        context = get_agent_object_context(session, "private-runbook", detail_access)
        assert context is not None and context.visibility == "detail"
        assert context.data["applies_to"] == ["system:visible-target"]
        assert [
            item.id
            for item in search_agent_objects(
                session,
                detail_access,
                search=SearchQuery(
                    runbook_status="active",
                    runbook_risk="read-only",
                    related_object="system:visible-target",
                ),
            )
        ] == ["private-runbook"]
        assert search_agent_objects(
            session,
            detail_access,
            search=SearchQuery(related_object="system:concealed-target"),
        ) == []

        stub_access = _reader(
            {"private-runbook": frozenset({Permission.DISCOVER})}
        )
        stub = search_agent_objects(session, stub_access)[0]
        rendered = stub.model_dump_json()
        for leaked in (
            '"runbook_status":"active"',
            '"runbook_risk":"read-only"',
            "status only",
            "Fictitious operating guide",
            "visible-target",
        ):
            assert leaked not in rendered
        assert search_agent_objects(
            session, stub_access, search=SearchQuery(runbook_status="active")
        ) == []
        assert search_agent_objects(
            session, stub_access, search=SearchQuery(runbook_risk="read-only")
        ) == []


def test_identical_write_is_revision_and_audit_free(
    alembic_session_factory,
) -> None:
    payload = _active_runbook("stable")
    with alembic_session_factory() as session:
        with transaction(session):
            created = upsert_object(session, payload)
            repeated = upsert_object(session, payload, expected_revision=created.revision)
            assert repeated.revision == created.revision == 1
            assert session.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.object_id == "stable")
            ) == 1


def test_runbook_migration_is_digest_bound_lossless_atomic_and_idempotent(
    alembic_session_factory,
) -> None:
    before = {
        "schema_version": 1,
        "old_notes": ["Preserve this unclassified free-form instruction."],
        "future_extension": {"preserved": True},
    }
    with alembic_session_factory() as session:
        with transaction(session):
            session.add(
                CatalogObject(
                    id="legacy",
                    kind="runbook",
                    label="Legacy",
                    status="active",
                    data_json=json.dumps(before, sort_keys=True),
                )
            )
        dry_run = build_runbook_migration_plan(session)
        assert {item.code for item in dry_run.diagnostics} == {
            "missing_approval_required",
            "missing_runbook_status",
        }
        assert json.loads(session.get(CatalogObject, "legacy").data_json) == before

        mapping = {
            "legacy": {
                "expected_data_sha256": runbook_data_sha256(before),
                "data_patch": {
                    "runbook_status": "draft",
                    "approval_required": False,
                },
            }
        }
        first = build_runbook_migration_plan(session, mapping)
        second = build_runbook_migration_plan(session, mapping)
        assert first.plan_digest == second.plan_digest
        assert first.diagnostics == () and len(first.changes) == 1
        assert first.changes[0].after["future_extension"] == {"preserved": True}
        with transaction(session):
            assert apply_runbook_migration_plan(session, first) == 1
        migrated = session.get(CatalogObject, "legacy")
        assert migrated.revision == 2
        assert json.loads(migrated.data_json)["old_notes"] == before["old_notes"]
        audit = session.scalar(
            select(AuditEvent).where(AuditEvent.object_id == "legacy")
        )
        assert audit is not None and audit.action == "runbook_normalize"
        assert json.loads(audit.details_json)["plan_digest"] == first.plan_digest

        rerun = build_runbook_migration_plan(session, mapping)
        assert rerun.diagnostics == () and rerun.changes == ()
        with transaction(session):
            assert apply_runbook_migration_plan(session, rerun) == 0
        assert session.get(CatalogObject, "legacy").revision == 2


def test_runbook_migration_rejects_stale_and_unsafe_plans(
    alembic_session_factory,
) -> None:
    before = {"schema_version": 1, "steps": ["Legacy free-form text."]}
    assert "unsafe_content" in classify_legacy_runbook(
        {"steps": [{"password": "must-not-be-kept"}]}
    )
    with alembic_session_factory() as session:
        with transaction(session):
            session.add(
                CatalogObject(
                    id="legacy-stale",
                    kind="runbook",
                    label="Legacy stale",
                    status="active",
                    data_json=json.dumps(before),
                )
            )
        stale = build_runbook_migration_plan(
            session,
            {
                "legacy-stale": {
                    "expected_data_sha256": "0" * 64,
                    "data_patch": {
                        "runbook_status": "draft",
                        "approval_required": False,
                    },
                }
            },
        )
        assert [item.code for item in stale.diagnostics] == ["fingerprint_mismatch"]
        with pytest.raises(RunbookMigrationError):
            apply_runbook_migration_plan(session, stale)


def test_runbook_migration_plan_detects_projected_supersession_cycles(
    alembic_session_factory,
) -> None:
    documents = {
        "first-legacy": {"schema_version": 1, "notes": "First."},
        "second-legacy": {"schema_version": 1, "notes": "Second."},
    }
    with alembic_session_factory() as session:
        with transaction(session):
            session.add_all(
                [
                    CatalogObject(
                        id=object_id,
                        kind="runbook",
                        label=object_id,
                        status="active",
                        data_json=json.dumps(data),
                    )
                    for object_id, data in documents.items()
                ]
            )
        mapping = {
            object_id: {
                "expected_data_sha256": runbook_data_sha256(data),
                "data_patch": {
                    "runbook_status": "superseded",
                    "approval_required": False,
                    "superseded_by": (
                        "runbook:second-legacy"
                        if object_id == "first-legacy"
                        else "runbook:first-legacy"
                    ),
                },
            }
            for object_id, data in documents.items()
        }
        plan = build_runbook_migration_plan(session, mapping)
        assert {
            (item.object_id, item.code) for item in plan.diagnostics
        } == {
            ("first-legacy", "invalid_supersession_graph"),
            ("second-legacy", "invalid_supersession_graph"),
        }


def test_runbook_schema_extensions_remain_preserved() -> None:
    payload = _runbook("extension", future_extension={"reviewed": True})
    assert payload.data["future_extension"] == {"reviewed": True}
    assert "runbook" in BUILTIN_SCHEMAS


def test_english_german_docs_publish_three_complete_valid_examples() -> None:
    document = (Path(__file__).parents[1] / "docs" / "runbooks.md").read_text(
        encoding="utf-8"
    )
    assert "## English contract" in document
    assert "## Deutscher Vertrag" in document
    examples = re.findall(r"```json\n(.*?)\n```", document, flags=re.DOTALL)
    assert len(examples) == 3
    validated = [
        CatalogObjectIn(
            id=f"documented-example-{index}",
            kind="runbook",
            label=f"Documented example {index}",
            data=json.loads(example),
        )
        for index, example in enumerate(examples, start=1)
    ]
    assert validated[0].data["risk_level"] == "read-only"
    assert validated[1].data["rollback"] and validated[1].data["verification"]
    assert validated[2].data["recovery"] and validated[2].data["credential_references"]


def test_schema_driven_ui_creates_and_renders_runbook_in_english_and_german(root_client, root_state) -> None:  # noqa: E501, F811
    owner_session = root_state["owner_session"]
    root_client.cookies.set(AUTH_SESSION_COOKIE_NAME, owner_session.value)
    root_client.cookies.set(AUTH_CSRF_COOKIE_NAME, owner_session.csrf_token)
    command = "  inspect-demo --format '${LITERAL}'  \n"
    response = root_client.post(
        "/roots",
        data={
            "csrf_token": owner_session.csrf_token,
            "idempotency_key": "runbook-ui-example-0001",
            "object_id": "ui-diagnosis",
            "kind": "runbook",
            "primary_name": "UI diagnosis",
            "runbook_status": "active",
            "purpose": "Diagnose the fictitious UI service.",
            "in_scope": "Read service health.",
            "out_of_scope": "Changing service state.",
            "risk_level": "read-only",
            "approval_required": "false",
            "prerequisite_id": "access",
            "prerequisite_description": "Confirm approved read access.",
            "step_id": "inspect",
            "step_title": "Inspect service",
            "step_command": command,
            "step_expected_effect": "The status is displayed without a change.",
            "verification_id": "healthy",
            "verification_description": "Review service health.",
            "verification_success_expectation": "The service reports healthy.",
            "last_verified_at": "2026-08-12T12:00:00Z",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text

    english = root_client.get("/objects/ui-diagnosis")
    assert english.status_code == 200
    assert "Operating and recovery contract" in english.text
    assert "Inert command text" in english.text
    assert "${LITERAL}" in english.text
    edit_match = re.search(r'href="([^"]+edit=runbook)"', english.text)
    assert edit_match is not None
    edit_href = unescape(edit_match.group(1))
    assert edit_href == "/objects/ui-diagnosis?view=catalog&q=&kind=&edit=runbook"
    edit = root_client.get(edit_href)
    assert edit.status_code == 200
    assert 'id="runbook-editor-title"' in edit.text
    assert 'name="runbook_status"' in edit.text
    assert "${LITERAL}" in edit.text
    german = root_client.get("/objects/ui-diagnosis?lang=de")
    assert german.status_code == 200
    assert "Betriebs- und Recovery-Vertrag" in german.text
    assert "Inerter Befehlstext" in german.text

    with root_state["session_factory"]() as session:
        stored = session.get(CatalogObject, "ui-diagnosis")
        assert stored is not None
        assert json.loads(stored.data_json)["steps"][0]["command"] == command


def test_runbook_detail_edit_navigation_respects_read_and_discover_only_access(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(
                session,
                _active_runbook(
                    "navigation-runbook",
                    purpose="Purpose visible only with read access.",
                ),
            )

    access = _reader(
        {
            "navigation-runbook": frozenset(
                {Permission.DISCOVER, Permission.READ}
            )
        }
    )
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with alembic_session_factory() as session:
            yield session

    def browser_access(request: Request) -> ReadAccess:
        request.state.read_access = access
        return access

    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[require_browser_read_access] = browser_access
    with TestClient(app) as client:
        read_only = client.get("/objects/navigation-runbook")
        assert read_only.status_code == 200
        assert "Purpose visible only with read access." in read_only.text
        assert "edit=runbook" not in read_only.text

        forced_edit = client.get("/objects/navigation-runbook?edit=runbook")
        assert forced_edit.status_code == 200
        assert 'id="runbook-title"' in forced_edit.text
        assert 'id="runbook-editor-title"' not in forced_edit.text
        assert "edit=runbook" not in forced_edit.text

        access = _reader(
            {"navigation-runbook": frozenset({Permission.DISCOVER})}
        )
        discover_only = client.get("/objects/navigation-runbook?edit=runbook")
        assert discover_only.status_code == 200
        assert "Purpose visible only with read access." not in discover_only.text
        assert 'id="runbook-title"' not in discover_only.text
        assert 'id="runbook-editor-title"' not in discover_only.text
        assert "edit=runbook" not in discover_only.text
