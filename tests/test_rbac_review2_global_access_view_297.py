# ruff: noqa: F811 -- imported PostgreSQL pytest fixtures.
"""R2 independent review repro (not product code): grant-less global principals
are omitted from the object access explanation."""

from test_rbac_boundaries_297 import context, seed  # noqa: E402

from blockwart.db.session import transaction  # noqa: E402
from blockwart.domain.auth import CatalogRole, Permission  # noqa: E402
from blockwart.services.grant_management import query_object_access  # noqa: E402
from blockwart.services.identity import create_service_account  # noqa: E402
from blockwart.services.policy import policy_for_principal  # noqa: E402


def test_grantless_global_reader_and_owner_listed_in_object_access(alembic_session_factory):
    with alembic_session_factory() as s:
        with transaction(s):
            _actor_id, owner_id = seed(s)
            reader = create_service_account(
                s,
                login="global-reader",
                display_name="Global Reader",
                catalog_role=CatalogRole.CATALOG_VIEWER,
            )
            gowner = create_service_account(
                s,
                login="global-owner",
                display_name="Global Owner",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            reader_id, gowner_id = reader.id, gowner.id
        assert policy_for_principal(s, reader_id).can(Permission.READ, "system")
        assert policy_for_principal(s, gowner_id).can(Permission.MANAGE_ACCESS, "system")
        view = query_object_access(s, context(s, owner_id), object_id="system")
        listed = {entry.principal.id: entry for entry in view.effective_access}
        assert reader_id in listed, (
            "Global Catalog Reader with READ is missing from effective_access"
        )
        assert gowner_id in listed, (
            "Global Catalog Owner with full rights is missing from effective_access"
        )
