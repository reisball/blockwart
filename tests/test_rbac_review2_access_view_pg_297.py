# ruff: noqa: F811 -- imported PostgreSQL pytest fixtures.
"""R2 review check (not product code): object access view on PostgreSQL."""

from sqlalchemy.orm import sessionmaker  # noqa: E402
from test_postgresql_compat_regressions import (  # noqa: F401,E402
    migrated_pg_engine,
    pg_database_name,
)
from test_rbac_boundaries_297 import context, seed  # noqa: E402

from blockwart.db.session import transaction  # noqa: E402
from blockwart.domain.auth import CatalogRole  # noqa: E402
from blockwart.services.grant_management import query_object_access  # noqa: E402
from blockwart.services.identity import create_service_account  # noqa: E402


def test_pg_object_access_view(migrated_pg_engine):
    factory = sessionmaker(bind=migrated_pg_engine, autoflush=False)
    with factory() as s, transaction(s):
        _actor_id, owner_id = seed(s, global_owner=True)
        create_service_account(
            s, login="global-reader", display_name="Reader", catalog_role=CatalogRole.CATALOG_VIEWER
        )
    with factory() as s:
        view = query_object_access(s, context(s, owner_id), object_id="system")
        reader = next(e for e in view.effective_access if e.principal.login == "global-reader")
        assert [a.source.value for a in reader.global_authorities] == ["catalog_viewer"]
        assert reader.sources == ()
