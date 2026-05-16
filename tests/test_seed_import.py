from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from blockwart.db.base import Base
from blockwart.db.session import build_engine
from blockwart.models import AuditEvent, CatalogObject, Relationship
from blockwart.services.seeds import import_seed_file

SEED_PATH = Path(__file__).resolve().parents[1] / "seeds" / "pilot_objects.yaml"


@pytest.fixture()
def session() -> Session:
    engine = build_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with session_factory() as db_session:
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
