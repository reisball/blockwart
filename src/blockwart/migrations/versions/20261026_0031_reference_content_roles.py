"""Add independently delegated credential-reference content roles. Refs #315.

Only the closed grant-role vocabulary changes. Existing principals, grants,
objects and timestamps are preserved; no viewer/editor receives a new role.
Owner and catalog-owner permissions are derived by policy, not data rewrites.
Downgrade refuses while either new role remains rather than dropping a grant
or translating it into a broader viewer/editor/owner assignment.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261026_0031"
down_revision = "20261023_0030"
branch_labels = None
depends_on = None

_OLD_ROLES = (
    "role IN "
    "('discoverer','viewer','renamer','editor','creator',"
    "'credential_reference_creator','access_manager','owner')"
)
_NEW_ROLES = (
    "role IN "
    "('discoverer','viewer','renamer','editor','creator',"
    "'credential_reference_creator','reference_content_reader',"
    "'reference_content_editor','access_manager','owner')"
)


def upgrade() -> None:
    _replace_grant_role_check(_NEW_ROLES)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # Keep the preflight and constraint replacement atomic with respect to
        # grant writers. SQLite migration transactions already serialize writes.
        bind.execute(sa.text("LOCK TABLE object_grants IN ACCESS EXCLUSIVE MODE"))
    content_grants = bind.scalar(
        sa.text(
            "SELECT COUNT(*) FROM object_grants "
            "WHERE role IN ('reference_content_reader','reference_content_editor')"
        )
    )
    if int(content_grants or 0):
        raise RuntimeError(
            "Reference content grants must be explicitly revoked before downgrade; "
            "restore the paired pre-migration backup if rollback is required"
        )
    _replace_grant_role_check(_OLD_ROLES)


def _replace_grant_role_check(expression: str) -> None:
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("object_grants", recreate="always") as batch:
            batch.drop_constraint("ck_object_grants_role", type_="check")
            batch.create_check_constraint("ck_object_grants_role", expression)
        return
    op.drop_constraint("ck_object_grants_role", "object_grants", type_="check")
    op.create_check_constraint("ck_object_grants_role", "object_grants", expression)
