"""Keep the public first-run example usable as schema/ownership rules evolve."""

from pathlib import Path

from sqlalchemy import select

from blockwart.config import Settings
from blockwart.db.readiness import check_database_readiness
from blockwart.db.session import transaction
from blockwart.domain.auth import CatalogRole
from blockwart.models import CatalogObject, Relationship
from blockwart.services.identity import create_service_account
from blockwart.services.seeds import import_seed_file


def test_quickstart_seed_is_startable_with_connected_operating_knowledge(alembic_database):
    with alembic_database.sessions() as session:
        with transaction(session):
            owner = create_service_account(
                session,
                login="example-owner",
                display_name="Example Owner",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            import_seed_file(
                session,
                Path(__file__).resolve().parents[1] / "seeds" / "quickstart.yaml",
                owner_principal_id=owner.id,
            )
        objects = {obj.id: obj for obj in session.scalars(select(CatalogObject))}
        assert set(objects) == {"demo-host", "demo-runtime", "demo-service", "demo-runbook"}
        assert all(objects[key].health == "unknown" for key in objects if key != "demo-runbook")
        edges = {
            (edge.from_ref, edge.relation_type, edge.to_ref)
            for edge in session.scalars(select(Relationship))
        }
        assert edges == {
            ("host:demo-host", "hosts", "system:demo-runtime"),
            ("system:demo-runtime", "hosts", "service:demo-service"),
            ("runbook:demo-runbook", "documents", "service:demo-service"),
        }

    # This also proves packaged-head migration, writable SQLite, complete active
    # Owner coverage and the independent global catalog-owner startup invariant.
    readiness = check_database_readiness(Settings(database_url=alembic_database.database_url))
    assert all(result == "ok" for result in readiness.checks.values())
