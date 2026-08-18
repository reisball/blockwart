from __future__ import annotations

import json
from collections.abc import Generator

import pytest
import yaml
from fastapi import Request
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from test_catalog_root_creation import root_client, root_state  # noqa: F401

from blockwart.api.deps import get_session
from blockwart.cli import database as database_cli
from blockwart.db.session import transaction
from blockwart.domain.auth import Permission, PrincipalContext, PrincipalType
from blockwart.domain.decisions import (
    DECISION_SOURCE_TYPE_VALUES,
    DECISION_STATUS_VALUES,
    DecisionIntegrityError,
)
from blockwart.domain.object_schema import BUILTIN_SCHEMAS
from blockwart.domain.schema_projection import kind_schema_projection
from blockwart.domain.ui_schema import ui_schema_payload
from blockwart.main import create_app
from blockwart.mcp.server import call_tool, describe_schema_payload
from blockwart.models import AuditEvent, CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.agent import get_agent_object_context, search_agent_objects
from blockwart.services.audit import render_audit_summary_english
from blockwart.services.catalog import get_object, upsert_object
from blockwart.services.commands import (
    CommandNotFound,
    WriteContext,
    update_catalog_object,
)
from blockwart.services.decision_migration import (
    apply_decision_migration_plan,
    build_decision_migration_plan,
    decision_data_sha256,
)
from blockwart.services.policy import PolicySnapshot
from blockwart.services.read_access import ReadAccess
from blockwart.ui.security import (
    AUTH_CSRF_COOKIE_NAME,
    AUTH_SESSION_COOKIE_NAME,
    require_browser_read_access,
    require_browser_write_csrf,
)


def _decision(object_id: str, status: str = "proposed", **data) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind="decision",
        label=object_id.replace("-", " ").title(),
        data={"schema_version": 1, "decision_status": status, **data},
    )


def _asset(object_id: str) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind="system",
        label=object_id,
        data={"schema_version": 1},
    )


def test_canonical_decision_schema_is_closed_and_projected_once() -> None:
    projection = kind_schema_projection("decision")
    fields = {field["path"]: field for field in projection["data"]["fields"]}

    assert set(fields["decision_status"]["enum"]) == set(DECISION_STATUS_VALUES)
    assert fields["decision_status"]["requirement"] == "required"
    assert fields["applies_to[]"]["reference_kinds"] == [
        "device",
        "host",
        "network",
        "service",
        "system",
    ]
    assert fields["related_projects[]"]["reference_kinds"] == ["project"]
    assert fields["related_runbooks[]"]["reference_kinds"] == ["runbook"]
    assert fields["related_decisions[]"]["reference_kinds"] == ["decision"]
    assert projection["decision"]["supersession"]["cycles_allowed"] is False
    assert describe_schema_payload("decision")["kinds"] == [projection]
    assert ui_schema_payload()["decision"]["object_schema"] == projection


def test_decision_ui_fields_and_source_contract_derive_from_canonical_schema() -> None:
    canonical = BUILTIN_SCHEMAS["decision"]
    expected_ui_fields = {
        field.path
        for field in canonical.fields
        if "." not in field.path
        and "[]" not in field.path
        and field.path != "schema_version"
        and field.forbidden_message is None
    }
    ui_fields = {
        field["storage_path"].removeprefix("data_json.")
        for field in ui_schema_payload()["decision"]["create_field_definitions"]
        if field["storage_path"].startswith("data_json.")
    }
    assert ui_fields == expected_ui_fields

    projection = kind_schema_projection("decision")
    fields = {field["path"]: field for field in projection["data"]["fields"]}
    assert fields["docs"]["max_items"] == 25
    assert fields["docs[]"]["additional_properties"] is False
    assert fields["docs[]"]["allowed_keys"] == [
        "published_at",
        "source_type",
        "title",
        "url",
    ]
    assert fields["docs[].source_type"]["enum"] == list(DECISION_SOURCE_TYPE_VALUES)
    assert fields["docs[].title"]["requirement"] == "required"
    assert fields["docs[].url"]["embedded_credentials_allowed"] is False
    assert projection["decision"]["external_sources"]["live_fetch"] is False


@pytest.mark.parametrize(
    ("entry", "path"),
    [
        ({"source_type": "original", "url": "https://example.invalid"}, "title"),
        (
            {
                "source_type": "original",
                "title": "Review",
                "url": "javascript:alert(1)",
            },
            "url",
        ),
        (
            {
                "source_type": "original",
                "title": "Review",
                "url": "data:text/plain,unsafe",
            },
            "url",
        ),
        (
            {
                "source_type": "original",
                "title": "Review",
                "url": "https://user:password@example.invalid/review",
            },
            "url",
        ),
        (
            {
                "source_type": "original",
                "title": "Review",
                "url": "https://example.invalid/review?token=opaque",
            },
            "url",
        ),
        (
            {
                "source_type": "original",
                "title": "Review",
                "url": "https://example.invalid/review",
                "script": "alert(1)",
            },
            "script",
        ),
    ],
)
def test_decision_source_entries_fail_with_field_accurate_paths(entry, path) -> None:
    with pytest.raises(ValidationError, match=rf"data\.docs\[0\]\.{path}"):
        _decision("unsafe-source", docs=[entry])


def test_decision_source_entries_normalize_and_apply_global_secret_safety() -> None:
    payload = _decision(
        "safe-source",
        docs=[
            {
                "source_type": "documentation",
                "title": "Deployment architecture",
                "url": "https://engineering.example/decisions/blue-green",
                "published_at": "2026-08-11T14:00:00+02:00",
            }
        ],
    )
    assert payload.data["docs"] == [
        {
            "source_type": "documentation",
            "title": "Deployment architecture",
            "url": "https://engineering.example/decisions/blue-green",
            "published_at": "2026-08-11T12:00:00Z",
        }
    ]
    with pytest.raises(ValidationError, match="raw secret"):
        _decision(
            "secret-source",
            docs=[
                {
                    "source_type": "original",
                    "title": "Bearer abcdefghijklmnopqrstuvwxyz123456",
                    "url": "https://example.invalid/source",
                }
            ],
        )


@pytest.mark.parametrize("field", ["context", "decision", "rationale", "decided_at"])
def test_accepted_decision_requires_complete_nonblank_record(field: str) -> None:
    data = {
        "context": "Current deployment is fragile.",
        "decision": "Adopt blue-green deployment.",
        "rationale": "It gives a bounded rollback.",
        "decided_at": "2026-08-11T12:00:00Z",
        "effective_at": "2026-08-12T12:00:00+00:00",
        "alternatives": ["In-place upgrade"],
        "consequences": ["Two environments during rollout"],
    }
    data[field] = "" if field != "decided_at" else None

    with pytest.raises(ValidationError, match=field):
        _decision("incomplete", "accepted", **data)


def test_decision_uses_global_secret_safety_contract() -> None:
    with pytest.raises(ValidationError, match="forbidden secret-shaped key"):
        _decision(
            "secret-shaped",
            alternatives=[{"password": "not-a-real-password"}],
        )


def test_decision_is_knowledge_and_timestamps_normalize_for_semantic_noop(
    alembic_session_factory,
) -> None:
    payload = _decision(
        "deploy-strategy",
        "accepted",
        context="  Current deployment is fragile.  ",
        decision="Adopt blue-green deployment.",
        rationale="Bounded rollback.",
        decided_at="2026-08-11T14:00:00+02:00",
        effective_at="2026-08-12T12:00:00Z",
    )
    assert payload.lifecycle is None
    assert payload.health is None
    assert payload.data["context"] == "Current deployment is fragile."
    assert payload.data["decided_at"] == "2026-08-11T12:00:00Z"
    with pytest.raises(ValidationError, match="only valid for asset kinds"):
        CatalogObjectIn(
            id="invalid-state",
            kind="decision",
            label="Invalid state",
            lifecycle="active",
            data={"schema_version": 1, "decision_status": "proposed"},
        )

    with alembic_session_factory() as session:
        with transaction(session):
            created = upsert_object(session, payload)
            repeated = upsert_object(
                session,
                _decision(
                    "deploy-strategy",
                    "accepted",
                    context="Current deployment is fragile.",
                    decision="Adopt blue-green deployment.",
                    rationale="Bounded rollback.",
                    decided_at="2026-08-11T12:00:00+00:00",
                    effective_at="2026-08-12T14:00:00+02:00",
                ),
                expected_revision=created.revision,
            )
            assert repeated.revision == created.revision == 1
            assert session.scalar(
                select(func.count()).select_from(AuditEvent).where(
                    AuditEvent.object_id == "deploy-strategy"
                )
            ) == 1


def test_supersession_rejects_self_reference_and_indirect_cycles(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _decision("first"))
            upsert_object(session, _decision("second"))
            upsert_object(session, _decision("third"))
            upsert_object(
                session,
                _decision(
                    "first",
                    "superseded",
                    superseded_by="decision:second",
                ),
            )
            with pytest.raises(DecisionIntegrityError, match="cycle"):
                upsert_object(
                    session,
                    _decision(
                        "second",
                        "superseded",
                        superseded_by="decision:first",
                    ),
                )
            upsert_object(
                session,
                _decision(
                    "second",
                    "superseded",
                    superseded_by="decision:third",
                ),
            )
            with pytest.raises(DecisionIntegrityError, match="cycle"):
                upsert_object(
                    session,
                    _decision(
                        "third",
                        "superseded",
                        superseded_by="decision:first",
                    ),
                )
            with pytest.raises(DecisionIntegrityError, match="itself"):
                upsert_object(
                    session,
                    _decision(
                        "self-link",
                        "superseded",
                        superseded_by="decision:self-link",
                    ),
                )


def test_legacy_decision_remains_readable_but_cannot_be_rewritten_free_form(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            session.add(
                CatalogObject(
                    id="legacy-decision",
                    kind="decision",
                    label="Legacy Decision",
                    status="active",
                    lifecycle=None,
                    health=None,
                    data_json='{"schema_version":1,"decision":"preserve"}',
                )
            )
        loaded = get_object(session, "legacy-decision")
        assert loaded is not None
        assert loaded.record_state == "valid"
        assert loaded.data["decision"] == "preserve"
        with pytest.raises(ValidationError, match="decision_status"):
            CatalogObjectIn.model_validate(loaded.model_dump())

        with transaction(session):
            session.add(
                CatalogObject(
                    id="legacy-statused-decision",
                    kind="decision",
                    label="Legacy statused Decision",
                    status="active",
                    lifecycle=None,
                    health=None,
                    data_json=json.dumps(
                        {
                            "schema_version": 1,
                            "decision_status": "proposed",
                            "alternatives": [{"free_form": "preserve exactly"}],
                        },
                        sort_keys=True,
                    ),
                )
            )
        statused = get_object(session, "legacy-statused-decision")
        assert statused is not None and statused.record_state == "valid"
        assert statused.data["alternatives"] == [{"free_form": "preserve exactly"}]
        with pytest.raises(ValidationError, match=r"data\.alternatives\[0\]"):
            CatalogObjectIn.model_validate(statused.model_dump())


def test_authorized_decision_context_and_filters_conceal_reference_targets(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _asset("visible-scope"))
            upsert_object(session, _asset("concealed-scope"))
            upsert_object(
                session,
                _decision(
                    "scoped-decision",
                    applies_to=["system:visible-scope", "system:concealed-scope"],
                ),
            )
        permissions = {
            "scoped-decision": frozenset({Permission.DISCOVER, Permission.READ}),
            "visible-scope": frozenset({Permission.DISCOVER}),
        }
        access = ReadAccess(
            principal=PrincipalContext(
                id="reader",
                principal_type=PrincipalType.HUMAN,
                login="reader",
                display_name="Reader",
            ),
            policy=PolicySnapshot("reader", permissions, {}),
        )
        context = get_agent_object_context(session, "scoped-decision", access)
        assert context is not None and context.visibility == "detail"
        assert context.data["applies_to"] == ["system:visible-scope"]
        assert context.applies_to == ["system:visible-scope"]
        assert [item.id for item in search_agent_objects(
            session,
            access,
            decision_status="proposed",
            applies_to="system:visible-scope",
        )] == ["scoped-decision"]
        assert search_agent_objects(
            session,
            access,
            applies_to="system:concealed-scope",
        ) == []
        assert search_agent_objects(
            session,
            access,
            query="concealed-scope",
        ) == []


def test_decision_write_requires_read_access_to_every_reference(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _asset("target"))
            upsert_object(session, _decision("write-decision"))
        context = WriteContext(
            principal=PrincipalContext(
                id="writer",
                principal_type=PrincipalType.SERVICE_ACCOUNT,
                login="writer",
                display_name="Writer",
            ),
            policy=PolicySnapshot(
                "writer",
                {"write-decision": frozenset({Permission.WRITE})},
                {},
            ),
            channel="api",
        )
        with pytest.raises(CommandNotFound):
            update_catalog_object(
                session,
                context,
                object_id="write-decision",
                payload=_decision("write-decision", applies_to=["system:target"]),
                expected_revision=1,
            )


def test_decision_migration_is_dry_run_first_and_apply_is_explicit(
    alembic_session_factory,
) -> None:
    before = {"schema_version": 1, "decision": "Keep the stable identifier."}
    with alembic_session_factory() as session:
        with transaction(session):
            session.add(
                CatalogObject(
                    id="legacy",
                    kind="decision",
                    label="Legacy",
                    status="active",
                    lifecycle=None,
                    health=None,
                    data_json=json.dumps(before, sort_keys=True),
                )
            )
        blocked = build_decision_migration_plan(session)
        assert [item.code for item in blocked.diagnostics] == ["missing_mapping"]
        assert json.loads(session.get(CatalogObject, "legacy").data_json) == before

        mapping = {
            "legacy": {
                "expected_data_sha256": decision_data_sha256(before),
                "data_patch": {
                    "decision_status": "accepted",
                    "context": "The identifier is already integrated.",
                    "rationale": "Changing it would break clients.",
                    "decided_at": "2026-08-11T12:00:00Z",
                },
            }
        }
        plan = build_decision_migration_plan(session, mapping)
        assert plan.diagnostics == ()
        assert len(plan.changes) == 1
        assert json.loads(session.get(CatalogObject, "legacy").data_json) == before
        with transaction(session):
            assert apply_decision_migration_plan(session, plan) == 1
        migrated = session.get(CatalogObject, "legacy")
        assert migrated is not None
        assert migrated.revision == 2
        assert json.loads(migrated.data_json)["decision_status"] == "accepted"
        audit = session.scalar(
            select(AuditEvent).where(AuditEvent.object_id == "legacy")
        )
        assert audit is not None
        assert audit.action == "decision_normalize"
        assert audit.actor == "decision-migration"
        assert render_audit_summary_english(
            audit.action,
            json.loads(audit.details_json),
            legacy_summary=audit.summary,
        ) == "Normalized Decision contract for decision:legacy"


def test_decision_migration_reports_planned_supersession_cycles(
    alembic_session_factory,
) -> None:
    first = {"schema_version": 1, "decision": "First legacy record."}
    second = {"schema_version": 1, "decision": "Second legacy record."}
    with alembic_session_factory() as session:
        with transaction(session):
            session.add_all(
                [
                    CatalogObject(
                        id=object_id,
                        kind="decision",
                        label=object_id.title(),
                        status="active",
                        lifecycle=None,
                        health=None,
                        data_json=json.dumps(data, sort_keys=True),
                    )
                    for object_id, data in (("first-legacy", first), ("second-legacy", second))
                ]
            )
        plan = build_decision_migration_plan(
            session,
            {
                "first-legacy": {
                    "expected_data_sha256": decision_data_sha256(first),
                    "data_patch": {
                        "decision_status": "superseded",
                        "superseded_by": "decision:second-legacy",
                    },
                },
                "second-legacy": {
                    "expected_data_sha256": decision_data_sha256(second),
                    "data_patch": {
                        "decision_status": "superseded",
                        "superseded_by": "decision:first-legacy",
                    },
                },
            },
        )
        assert {
            (diagnostic.object_id, diagnostic.code)
            for diagnostic in plan.diagnostics
        } == {
            ("first-legacy", "invalid_supersession_graph"),
            ("second-legacy", "invalid_supersession_graph"),
        }


def test_legacy_docs_are_blocked_without_guessing_and_require_explicit_mapping(
    alembic_session_factory,
) -> None:
    before = {
        "schema_version": 1,
        "decision_status": "proposed",
        "docs": ["https://legacy.example/review"],
    }
    with alembic_session_factory() as session:
        with transaction(session):
            session.add(
                CatalogObject(
                    id="legacy-docs",
                    kind="decision",
                    label="Legacy docs",
                    status="active",
                    lifecycle=None,
                    health=None,
                    data_json=json.dumps(before, sort_keys=True),
                )
            )
        dry_run = build_decision_migration_plan(session)
        assert [(item.object_id, item.code) for item in dry_run.diagnostics] == [
            ("legacy-docs", "invalid_canonical_decision")
        ]
        assert json.loads(session.get(CatalogObject, "legacy-docs").data_json) == before

        mapping = {
            "legacy-docs": {
                "expected_data_sha256": decision_data_sha256(before),
                "data_patch": {
                    "docs": [
                        {
                            "source_type": "original",
                            "title": "Reviewed legacy source",
                            "url": "https://legacy.example/review",
                        }
                    ]
                },
            }
        }
        planned = build_decision_migration_plan(session, mapping)
        assert planned.diagnostics == ()
        assert len(planned.changes) == 1
        assert json.loads(session.get(CatalogObject, "legacy-docs").data_json) == before


def test_decision_migration_cli_dry_run_does_not_modify_sqlite(
    tmp_path,
    capsys,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'decisions.sqlite3'}"
    assert database_cli.main(["--database-url", database_url, "upgrade"]) == 0
    capsys.readouterr()
    from sqlalchemy import create_engine

    engine = create_engine(database_url)
    before = {"schema_version": 1, "decision": "Preserve this text."}
    try:
        with engine.begin() as connection:
            connection.execute(
                CatalogObject.__table__.insert().values(
                    id="legacy-cli",
                    kind="decision",
                    label="Legacy CLI",
                    status="active",
                    lifecycle=None,
                    health=None,
                    data_json=json.dumps(before, sort_keys=True),
                )
            )
        mapping_path = tmp_path / "decisions.yaml"
        mapping_path.write_text(
            yaml.safe_dump(
                {
                    "version": 1,
                    "decisions": [
                        {
                            "object_id": "legacy-cli",
                            "expected_data_sha256": decision_data_sha256(before),
                            "data_patch": {"decision_status": "proposed"},
                        }
                    ],
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        arguments = [
            "--database-url",
            database_url,
            "--mapping",
            str(mapping_path),
        ]
        assert database_cli.main([*arguments, "decisions"]) == 0
        assert "mode=dry-run scanned=1 canonical=0 changed=1 blocked=0" in (
            capsys.readouterr().out
        )
        with engine.connect() as connection:
            assert json.loads(
                connection.scalar(
                    select(CatalogObject.data_json).where(
                        CatalogObject.id == "legacy-cli"
                    )
                )
            ) == before
        assert database_cli.main([*arguments, "--apply", "decisions"]) == 0
        assert "mode=apply scanned=1 canonical=0 changed=1 blocked=0" in (
            capsys.readouterr().out
        )
        with engine.connect() as connection:
            migrated = json.loads(
                connection.scalar(
                    select(CatalogObject.data_json).where(
                        CatalogObject.id == "legacy-cli"
                    )
                )
            )
            assert migrated == {**before, "decision_status": "proposed"}
    finally:
        engine.dispose()


@pytest.fixture
def decision_client(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> Generator[TestClient, None, None]:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _asset("api-scope"))
            upsert_object(
                session,
                _decision(
                    "api-decision",
                    "accepted",
                    context="A context",
                    decision="A decision",
                    rationale="A rationale",
                    decided_at="2026-08-11T12:00:00Z",
                    applies_to=["system:api-scope"],
                ),
            )
    app = create_app()
    install_unrestricted_read_access(app)

    def override_get_session() -> Generator[Session, None, None]:
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        yield client


def test_rest_agent_and_mcp_share_decision_filters(decision_client: TestClient) -> None:
    params = {"decision_status": "accepted", "applies_to": "system:api-scope"}
    v1 = decision_client.get("/api/v1/objects", params=params)
    agent = decision_client.get("/api/agent/context", params=params)
    assert v1.status_code == agent.status_code == 200
    assert [item["id"] for item in v1.json()["items"]] == ["api-decision"]
    assert [item["id"] for item in agent.json()["objects"]] == ["api-decision"]
    assert v1.json()["items"][0]["decision_status"] == "accepted"
    assert v1.json()["items"][0]["applies_to"] == ["system:api-scope"]

    seen: dict[str, object] = {}

    def fetcher(path: str, forwarded: dict) -> dict:
        seen.update({"path": path, "params": forwarded})
        return {"items": [], "next_cursor": None, "total": None}

    call_tool("blockwart.search", params, fetcher=fetcher)
    assert seen == {
        "path": "/api/v1/objects",
        "params": {**params, "q": None, "kind": None, "limit": 10},
    }


def test_ui_never_renders_or_silently_discards_unsafe_legacy_source_values(
    decision_client: TestClient,
    alembic_session_factory,
) -> None:
    unsafe_url = "https://user:password@legacy.example/source"
    before = {
        "schema_version": 1,
        "decision_status": "proposed",
        "docs": [
            {
                "source_type": "original",
                "title": "Legacy source",
                "url": unsafe_url,
            }
        ],
    }
    with alembic_session_factory() as session:
        with transaction(session):
            session.add(
                CatalogObject(
                    id="unsafe-legacy-source",
                    kind="decision",
                    label="Unsafe legacy source",
                    status="active",
                    lifecycle=None,
                    health=None,
                    data_json=json.dumps(before, sort_keys=True),
                )
            )

    detail = decision_client.get("/objects/unsafe-legacy-source")
    assert detail.status_code == 200
    assert unsafe_url not in detail.text
    assert "Legacy source values are preserved" in detail.text
    edit = decision_client.get("/objects/unsafe-legacy-source?edit=decision")
    assert edit.status_code == 200
    assert unsafe_url not in edit.text

    with alembic_session_factory() as session:
        row = session.get(CatalogObject, "unsafe-legacy-source")
        assert row is not None
        assert json.loads(row.data_json) == before


def test_ui_conceals_reference_labels_and_preserves_hidden_links_on_write(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _asset("visible-ui-target"))
            upsert_object(session, _asset("concealed-ui-target"))
            upsert_object(
                session,
                _decision(
                    "ui-concealment",
                    applies_to=[
                        "system:visible-ui-target",
                        "system:concealed-ui-target",
                    ],
                ),
            )

    permissions = {
        "ui-concealment": frozenset(
            {Permission.DISCOVER, Permission.READ, Permission.WRITE}
        ),
        "visible-ui-target": frozenset({Permission.DISCOVER}),
    }
    access = ReadAccess(
        principal=PrincipalContext(
            id="ui-concealment-reader",
            principal_type=PrincipalType.HUMAN,
            login="ui.concealment.reader",
            display_name="UI concealment reader",
        ),
        policy=PolicySnapshot("ui-concealment-reader", permissions, {}),
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
    app.dependency_overrides[require_browser_write_csrf] = lambda: None
    with TestClient(app) as client:
        detail = client.get("/objects/ui-concealment")
        assert detail.status_code == 200
        assert "visible-ui-target" in detail.text
        assert "concealed-ui-target" not in detail.text

        denied = client.post(
            "/objects/ui-concealment",
            data={
                "if_match": '"rev-1"',
                "decision_status": "proposed",
                "applies_to": "system:visible-ui-target",
            },
        )
        assert denied.status_code == 404
        assert "concealed-ui-target" not in denied.text

    with alembic_session_factory() as session:
        unchanged = get_object(session, "ui-concealment")
        assert unchanged is not None and unchanged.revision == 1
        assert unchanged.data["applies_to"] == [
            "system:visible-ui-target",
            "system:concealed-ui-target",
        ]


def test_rest_and_ui_write_canonical_decisions(
    root_client,  # noqa: F811
    root_state,  # noqa: F811
) -> None:
    accepted_data = {
        "schema_version": 1,
        "decision_status": "accepted",
        "context": "A reviewed context.",
        "decision": "Use the canonical model.",
        "rationale": "All boundaries then agree.",
        "decided_at": "2026-08-11T12:00:00Z",
    }
    api_response = root_client.post(
        "/api/v1/roots",
        headers={
            "Authorization": f"Bearer {root_state['owner_token']}",
            "Idempotency-Key": "test-test-test-six",
        },
        json={
            "id": "api-root-decision",
            "kind": "decision",
            "label": "API root Decision",
            "data": accepted_data,
        },
    )
    assert api_response.status_code == 201
    assert api_response.json()["catalog_object"]["data"] == accepted_data

    invalid_source = root_client.post(
        "/api/v1/roots",
        headers={
            "Authorization": f"Bearer {root_state['owner_token']}",
            "Idempotency-Key": "decision-api-invalid-source-0001",
        },
        json={
            "id": "api-invalid-source",
            "kind": "decision",
            "label": "Invalid source",
            "data": {
                "schema_version": 1,
                "decision_status": "proposed",
                "docs": [
                    {
                        "source_type": "original",
                        "title": "Unsafe source",
                        "url": "javascript:alert(1)",
                    }
                ],
            },
        },
    )
    assert invalid_source.status_code == 422
    assert invalid_source.json()["error"]["details"][0]["path"] == "data.docs[0].url"

    root_client.cookies.set(AUTH_SESSION_COOKIE_NAME, root_state["owner_session"].value)
    root_client.cookies.set(
        AUTH_CSRF_COOKIE_NAME,
        root_state["owner_session"].csrf_token,
    )
    ui_response = root_client.post(
        "/roots",
        data={
            "csrf_token": root_state["owner_session"].csrf_token,
            "idempotency_key": "decision-ui-root-0001",
            "object_id": "ui-root-decision",
            "kind": "decision",
            "primary_name": "UI root Decision",
            "status": "active",
            "summary": "Created through the UI.",
            "decision_status": "proposed",
        },
        follow_redirects=False,
    )
    assert ui_response.status_code == 303
    with root_state["session_factory"]() as session:
        created = get_object(session, "ui-root-decision")
        assert created is not None
        assert created.data["decision_status"] == "proposed"


def test_ui_publishes_and_renders_canonical_decision_schema(
    decision_client: TestClient,
) -> None:
    response = decision_client.get("/settings/schema?kind=decision")
    assert response.status_code == 200
    assert '<option value="decision" selected>' in response.text
    assert "Decision status" in response.text
    assert "Documentation and original sources" in response.text
    assert "source-list" in response.text
    assert '"decision_status"' in response.text


def test_structured_ui_create_detail_noop_edit_and_supersession_round_trip(
    root_client,  # noqa: F811
    root_state,  # noqa: F811
) -> None:
    headers = {
        "Authorization": f"Bearer {root_state['owner_token']}",
    }

    def create_root(object_id: str, kind: str, data: dict) -> None:
        response = root_client.post(
            "/api/v1/roots",
            headers={**headers, "Idempotency-Key": f"decision-ui-{object_id}"},
            json={
                "id": object_id,
                "kind": kind,
                "label": object_id.replace("-", " ").title(),
                "data": data,
            },
        )
        assert response.status_code == 201, response.text

    create_root("decision-scope", "system", {"schema_version": 1})
    create_root(
        "decision-project",
        "project",
        {
            "schema_version": 1,
            "category": "implementation",
            "project_status": "planned",
        },
    )
    create_root(
        "decision-runbook",
        "runbook",
        {
            "schema_version": 1,
            "runbook_status": "draft",
            "approval_required": False,
        },
    )
    create_root(
        "related-decision",
        "decision",
        {"schema_version": 1, "decision_status": "proposed"},
    )

    root_client.cookies.set(AUTH_SESSION_COOKIE_NAME, root_state["owner_session"].value)
    root_client.cookies.set(
        AUTH_CSRF_COOKIE_NAME,
        root_state["owner_session"].csrf_token,
    )
    decision_form = {
        "csrf_token": root_state["owner_session"].csrf_token,
        "idempotency_key": "test-test-test-seven",
        "object_id": "deploy-blue-green",
        "kind": "decision",
        "primary_name": "Use blue-green deployment",
        "status": "active",
        "summary": "The production release strategy.",
        "decision_status": "accepted",
        "context": "In-place releases make rollback unpredictable.",
        "decision": "Deploy with a blue-green environment pair.",
        "rationale": "Traffic switching creates a bounded rollback.",
        "alternatives": "Continue in-place upgrades\nAdopt canary releases",
        "consequences": "Operate two environments\nReserve failover capacity",
        "decided_at": "2026-08-11T12:00:00Z",
        "effective_at": "2026-08-18T08:00:00Z",
        "review_after": "2027-02-11T12:00:00Z",
        "applies_to": "system:decision-scope",
        "related_projects": "project:decision-project",
        "related_runbooks": "runbook:decision-runbook",
        "related_decisions": "decision:related-decision",
        "supersedes": "",
        "superseded_by": "",
        "doc_source_type": ["original"],
        "doc_title": ["Architecture review record"],
        "doc_url": ["https://engineering.example/records/blue-green"],
        "doc_published_at": ["2026-08-11T12:00:00Z"],
    }
    invalid_form = {
        **decision_form,
        "idempotency_key": "decision-ui-invalid-source-0001",
        "object_id": "invalid-source-ui",
        "decision_status": "proposed",
        "context": "",
        "decision": "",
        "rationale": "",
        "decided_at": "",
        "doc_url": ["javascript:alert(1)"],
    }
    invalid = root_client.post("/roots", data=invalid_form)
    assert invalid.status_code == 422
    assert "Check Documentation and original sources" in invalid.text
    assert "javascript:alert(1)" not in invalid.text

    secret_marker = "Bearer abcdefghijklmnopqrstuvwxyz123456"
    secret_form = {
        **invalid_form,
        "idempotency_key": "decision-ui-secret-source-0001",
        "object_id": "secret-source-ui",
        "doc_title": [secret_marker],
        "doc_url": ["https://example.invalid/source"],
    }
    secret = root_client.post("/roots", data=secret_form)
    assert secret.status_code == 422
    assert secret_marker not in secret.text

    created = root_client.post("/roots", data=decision_form, follow_redirects=False)
    assert created.status_code == 303, created.text

    detail = root_client.get("/objects/deploy-blue-green")
    assert detail.status_code == 200
    for expected in (
        "Status and validity",
        "Context, Decision, and rationale",
        "Alternatives and consequences",
        "Affected assets",
        "Related knowledge",
        "Supersession",
        "Documentation and original sources",
        "Architecture review record",
    ):
        assert expected in detail.text
    assert 'href="https://engineering.example/records/blue-green"' in detail.text
    assert 'target="_blank" rel="noopener noreferrer"' in detail.text
    assert 'name="data_json"' not in detail.text

    edit = root_client.get("/objects/deploy-blue-green?edit=decision")
    assert edit.status_code == 200
    for field_name in (
        "decision_status",
        "context",
        "decision",
        "rationale",
        "alternatives",
        "consequences",
        "decided_at",
        "effective_at",
        "review_after",
        "applies_to",
        "related_projects",
        "related_runbooks",
        "related_decisions",
        "supersedes",
        "superseded_by",
        "doc_source_type",
        "doc_title",
        "doc_url",
        "doc_published_at",
    ):
        assert f'name="{field_name}"' in edit.text
    assert 'name="if_match"' in edit.text
    assert "rev-1" in edit.text

    with root_state["session_factory"]() as session:
        row = session.get(CatalogObject, "deploy-blue-green")
        assert row is not None
        stored = json.loads(row.data_json)
        stored["legacy_extension"] = {"preserve": "verbatim"}
        row.data_json = json.dumps(stored, sort_keys=True)
        session.commit()
        initial_audits = session.scalar(
            select(func.count()).select_from(AuditEvent).where(
                AuditEvent.object_id == "deploy-blue-green"
            )
        )

    edit_form = {
        key: value
        for key, value in decision_form.items()
        if key not in {"idempotency_key", "object_id", "kind", "primary_name", "status", "summary"}
    }
    edit_form["if_match"] = '"rev-1"'
    no_op = root_client.post(
        "/objects/deploy-blue-green",
        data=edit_form,
        follow_redirects=False,
    )
    assert no_op.status_code == 303, no_op.text
    with root_state["session_factory"]() as session:
        unchanged = session.get(CatalogObject, "deploy-blue-green")
        assert unchanged is not None
        assert unchanged.revision == 1
        assert json.loads(unchanged.data_json)["legacy_extension"] == {
            "preserve": "verbatim"
        }
        assert session.scalar(
            select(func.count()).select_from(AuditEvent).where(
                AuditEvent.object_id == "deploy-blue-green"
            )
        ) == initial_audits

    comment = root_client.post(
        "/objects/deploy-blue-green/comments",
        data={
            "csrf_token": root_state["owner_session"].csrf_token,
            "comment": "Review follow-up belongs to the comment stream.",
            "idempotency_key": "decision-comment-0001",
        },
        follow_redirects=False,
    )
    assert comment.status_code == 303
    with root_state["session_factory"]() as session:
        unchanged = session.get(CatalogObject, "deploy-blue-green")
        assert unchanged is not None and unchanged.revision == 2
        assert session.scalar(
            select(func.count()).select_from(AuditEvent).where(
                AuditEvent.object_id == "deploy-blue-green",
                AuditEvent.action == "comment_create",
            )
        ) == 1

    create_root(
        "deploy-progressive",
        "decision",
        {
            "schema_version": 1,
            "decision_status": "accepted",
            "context": "Blue-green capacity is costly.",
            "decision": "Adopt progressive delivery.",
            "rationale": "Smaller cohorts reduce idle capacity.",
            "decided_at": "2027-02-11T12:00:00Z",
            "supersedes": ["decision:deploy-blue-green"],
        },
    )
    edit_form.update(
        {
            "decision_status": "superseded",
            "superseded_by": "decision:deploy-progressive",
            "if_match": '"rev-2"',
        }
    )
    superseded = root_client.post(
        "/objects/deploy-blue-green",
        data=edit_form,
        follow_redirects=False,
    )
    assert superseded.status_code == 303, superseded.text
    with root_state["session_factory"]() as session:
        updated = session.get(CatalogObject, "deploy-blue-green")
        assert updated is not None and updated.revision == 3
        updated_data = json.loads(updated.data_json)
        assert updated_data["decision_status"] == "superseded"
        assert updated_data["superseded_by"] == "decision:deploy-progressive"
        assert updated_data["legacy_extension"] == {"preserve": "verbatim"}

    superseded_detail = root_client.get("/objects/deploy-blue-green")
    assert "Superseded" in superseded_detail.text
    assert "Deploy Progressive" in superseded_detail.text
    german_detail = root_client.get(
        "/objects/deploy-blue-green?lang=de",
        headers={"Accept-Language": "de"},
    )
    assert german_detail.status_code == 200
    for expected in (
        "Status und Gültigkeit",
        "Kontext, Entscheidung und Begründung",
        "Betroffene Assets",
        "Dokumentation und Originalquellen",
    ):
        assert expected in german_detail.text
