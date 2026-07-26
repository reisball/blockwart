from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from blockwart.domain.provenance import load_provenance
from blockwart.models import AuditEvent, CatalogObject, Relationship
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import upsert_object
from blockwart.services.seeds import import_seed_file, import_seed_payload

SEED_PATH = Path(__file__).resolve().parents[1] / "seeds" / "pilot_objects.yaml"


@pytest.fixture()
def session(alembic_session_factory) -> Session:
    with alembic_session_factory() as db_session:
        yield db_session


def test_import_pilot_seed_into_fresh_db(session: Session) -> None:
    result = import_seed_file(session, SEED_PATH)

    assert result.objects_imported >= 8
    object_count = session.scalar(select(func.count()).select_from(CatalogObject))

    assert object_count == result.objects_imported
    assert session.scalar(select(func.count()).select_from(Relationship)) == (
        result.relationships_imported
    )
    assert session.scalar(select(func.count()).select_from(AuditEvent)) == (
        result.objects_imported + result.relationships_imported
    )

    systems = set(session.scalars(select(CatalogObject.id).where(CatalogObject.kind == "system")))
    assert systems == {
        "fabrik",
        "denkstube",
        "n8n",
        "brieftraeger",
        "paperless-ngx",
        "vaultwarden",
        "ollama",
        "splunk",
    }
    asset_states = session.execute(
        select(
            CatalogObject.status,
            CatalogObject.lifecycle,
            CatalogObject.health,
        ).where(CatalogObject.kind.in_({"host", "system", "netzwerk", "service"}))
    ).all()
    assert asset_states
    assert all(
        lifecycle is not None and health is not None
        for _, lifecycle, health in asset_states
    )
    assert all(
        (status, lifecycle, health) == ("active", "active", "unknown")
        for status, lifecycle, health in asset_states
    )
    knowledge_states = session.execute(
        select(CatalogObject.lifecycle, CatalogObject.health).where(
            CatalogObject.kind.in_(
                {"credential_reference", "runbook", "decision", "project"}
            )
        )
    ).all()
    assert knowledge_states
    assert all(state == (None, None) for state in knowledge_states)
    fabrik = session.get(CatalogObject, "fabrik")
    assert fabrik is not None
    provenance, valid = load_provenance(fabrik.provenance_json)
    assert valid is True
    assert provenance.source_type == "import"
    assert provenance.source_ref == str(SEED_PATH)
    assert provenance.managed_by == "Kai + Zoe"
    assert provenance.observed_at == "2026-05-16T00:00:00.000000Z"
    assert provenance.verified_at == "2026-05-16T00:00:00.000000Z"
    assert provenance.manual_override is False


def test_seed_does_not_silently_overwrite_manual_override(session: Session) -> None:
    payload = {
        "schema_version": 1,
        "objects": [
            {
                "id": "protected",
                "kind": "service",
                "label": "Imported",
                "data": {"schema_version": 1, "purpose": "imported"},
            }
        ],
        "relationships": [],
    }
    assert import_seed_payload(session, payload).objects_imported == 1
    upsert_object(
        session,
        CatalogObjectIn(
            id="protected",
            kind="service",
            label="Manual",
            data={"schema_version": 1, "purpose": "manual"},
        ),
    )

    result = import_seed_payload(session, payload)
    row = session.get(CatalogObject, "protected")

    assert result.objects_imported == 0
    assert row is not None
    assert row.label == "Manual"
    assert '"purpose": "manual"' in row.data_json
    provenance, valid = load_provenance(row.provenance_json)
    assert valid is True
    assert provenance.source_type == "manual"
    assert provenance.manual_override is True


def test_seed_accepts_explicit_asset_state_and_derives_compatibility_status(
    session: Session,
) -> None:
    result = import_seed_payload(
        session,
        {
            "schema_version": 1,
            "objects": [
                {
                    "id": "maintenance-api",
                    "kind": "service",
                    "label": "Maintenance API",
                    "lifecycle": "active",
                    "health": "maintenance",
                    "data": {"schema_version": 1},
                }
            ],
            "relationships": [],
        },
    )
    row = session.get(CatalogObject, "maintenance-api")

    assert result.objects_imported == 1
    assert row is not None
    assert (row.status, row.lifecycle, row.health) == (
        "inactive",
        "active",
        "maintenance",
    )


def test_pilot_seed_imports_core_ids_and_kinds(session: Session) -> None:
    import_seed_file(session, SEED_PATH)

    expected = {
        "fabrik": "system",
        "n8n-web-ui": "service",
        "brieftraeger-ssh-login": "credential_reference",
        "runbook-check-ollama-api": "runbook",
    }
    rows = session.scalars(select(CatalogObject).where(CatalogObject.id.in_(expected))).all()

    assert {row.id: row.kind for row in rows} == expected


def test_pilot_seed_relationship_references_existing_objects(session: Session) -> None:
    import_seed_file(session, SEED_PATH)

    object_refs = {
        f"{kind}:{object_id}"
        for object_id, kind in session.execute(select(CatalogObject.id, CatalogObject.kind)).all()
    }
    relationships = session.scalars(select(Relationship)).all()

    assert relationships
    for relationship in relationships:
        assert relationship.from_ref in object_refs
        assert relationship.to_ref in object_refs


def test_pilot_seed_rejects_secret_shaped_values(session: Session, tmp_path: Path) -> None:
    forbidden_seed = tmp_path / "forbidden.yaml"
    forbidden_seed.write_text(
        """
schema_version: 1
objects:
  - id: bad
    kind: system
    label: Bad
    status: active
    data:
      password: not-allowed
relationships: []
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        import_seed_file(session, forbidden_seed)


def test_pilot_seed_rejects_unsafe_credential_reference_rules(
    session: Session,
    tmp_path: Path,
) -> None:
    forbidden_seed = tmp_path / "unsafe-credential-reference.yaml"
    forbidden_seed.write_text(
        """
schema_version: 1
objects:
  - id: unsafe-credential-reference
    kind: credential_reference
    label: Unsafe credential reference
    status: active
    data:
      schema_version: 1
      provider: vaultwarden
      reference:
        name: Example
      scope:
        access_type: api
        systems: []
        services: []
      handling_rules:
        telegram_allowed: true
        markdown_secret_allowed: false
        agents_may_read_value: false
      secret_value_stored: false
relationships: []
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        import_seed_file(session, forbidden_seed)


def test_pilot_seed_rejects_missing_relationship_targets(session: Session, tmp_path: Path) -> None:
    forbidden_seed = tmp_path / "missing-reference.yaml"
    forbidden_seed.write_text(
        """
schema_version: 1
objects:
  - id: known
    kind: system
    label: Known
    status: active
    data: {}
relationships:
  - from_ref: system:known
    relation_type: depends_on
    to_ref: system:missing
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        import_seed_file(session, forbidden_seed)


def test_seed_object_ids_are_globally_unique_across_kinds(session: Session) -> None:
    payload = {
        "schema_version": 1,
        "objects": [
            {
                "id": "shared-id",
                "kind": "host",
                "label": "Hardware",
                "data": {},
            },
            {
                "id": "shared-id",
                "kind": "system",
                "label": "Runtime",
                "data": {},
            },
        ],
        "relationships": [],
    }

    with pytest.raises(
        ValueError,
        match="Seed object ids must be globally unique across kinds",
    ):
        import_seed_payload(session, payload)
