"""allow the narrow object-grant role ``renamer``

Revision ID: 20260909_0022
Revises: 20260825_0021

The migration only expands the closed object-grant role vocabulary by the new
narrow ``renamer`` role. It writes no grant, assigns no role, and rewrites no
existing row: the ``rename`` permission that ``editor``, ``owner``, and
``catalog_owner`` gain is derived in the policy service from the role each
grant already stores, so every existing assignment keeps working unchanged
without being touched here.

A downgrade fails closed while any grant still carries ``renamer`` because the
preceding schema cannot represent that value without silently dropping the
authorization it expresses. ``object_grants`` carries no trigger, so the SQLite
table rebuild that replaces the check constraint restores the table with its
constraints and indexes only.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260909_0022"
down_revision: str | Sequence[str] | None = "20260825_0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLES_WITHOUT_RENAMER = (
    "role IN ('discoverer','viewer','editor','creator','access_manager','owner')"
)
_ROLES_WITH_RENAMER = (
    "role IN "
    "('discoverer','viewer','renamer','editor','creator','access_manager','owner')"
)


def upgrade() -> None:
    _replace_grant_role_check(_ROLES_WITH_RENAMER)


def downgrade() -> None:
    bind = op.get_bind()
    renamer_count = bind.scalar(
        sa.text("SELECT COUNT(*) FROM object_grants WHERE role = 'renamer'")
    )
    if int(renamer_count or 0) != 0:
        raise RuntimeError(
            "Renamer grants must be explicitly revoked before downgrade; "
            "restore the paired pre-migration backup if rollback is required"
        )
    _replace_grant_role_check(_ROLES_WITHOUT_RENAMER)


def _replace_grant_role_check(expression: str) -> None:
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("object_grants", recreate="always") as batch:
            batch.drop_constraint("ck_object_grants_role", type_="check")
            batch.create_check_constraint("ck_object_grants_role", expression)
        return
    op.drop_constraint("ck_object_grants_role", "object_grants", type_="check")
    op.create_check_constraint("ck_object_grants_role", "object_grants", expression)
