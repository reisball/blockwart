"""add the independent global catalog-owner role to principals

Revision ID: 20260806_0015
Revises: 20260804_0014

The upgrade is purely additive: it adds a nullable, indexed `catalog_role`
column and its value constraint. It never promotes an existing principal and
never creates an object grant, so an upgraded installation reaches the strict
`catalog_owner_missing` readiness gate until an operator explicitly selects the
first catalog owner through the protected CLI.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260806_0015"
down_revision: str | Sequence[str] | None = "20260804_0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# The batch table rebuild required for the new check constraint drops every
# trigger attached to `principals`, so revision 20260731_0012's last-admin
# guards are recreated verbatim on upgrade and downgrade.
_LAST_ADMIN_UPDATE_TRIGGER = """
CREATE TRIGGER ck_principals_last_active_admin_update
BEFORE UPDATE OF active, platform_role ON principals
WHEN OLD.active = 1
  AND OLD.platform_role = 'admin'
  AND (NEW.active = 0 OR NEW.platform_role IS NULL OR NEW.platform_role <> 'admin')
  AND NOT EXISTS (
    SELECT 1 FROM principals
    WHERE id <> OLD.id AND active = 1 AND platform_role = 'admin'
  )
BEGIN
  SELECT RAISE(ABORT, 'last active platform admin');
END
"""

_LAST_ADMIN_DELETE_TRIGGER = """
CREATE TRIGGER ck_principals_last_active_admin_delete
BEFORE DELETE ON principals
WHEN OLD.active = 1
  AND OLD.platform_role = 'admin'
  AND NOT EXISTS (
    SELECT 1 FROM principals
    WHERE id <> OLD.id AND active = 1 AND platform_role = 'admin'
  )
BEGIN
  SELECT RAISE(ABORT, 'last active platform admin');
END
"""

_LAST_CATALOG_OWNER_UPDATE_TRIGGER = """
CREATE TRIGGER ck_principals_last_active_catalog_owner_update
BEFORE UPDATE OF active, catalog_role ON principals
WHEN OLD.active = 1
  AND OLD.catalog_role = 'catalog_owner'
  AND (NEW.active = 0 OR NEW.catalog_role IS NULL OR NEW.catalog_role <> 'catalog_owner')
  AND NOT EXISTS (
    SELECT 1 FROM principals
    WHERE id <> OLD.id AND active = 1 AND catalog_role = 'catalog_owner'
  )
BEGIN
  SELECT RAISE(ABORT, 'last active catalog owner');
END
"""

_LAST_CATALOG_OWNER_DELETE_TRIGGER = """
CREATE TRIGGER ck_principals_last_active_catalog_owner_delete
BEFORE DELETE ON principals
WHEN OLD.active = 1
  AND OLD.catalog_role = 'catalog_owner'
  AND NOT EXISTS (
    SELECT 1 FROM principals
    WHERE id <> OLD.id AND active = 1 AND catalog_role = 'catalog_owner'
  )
BEGIN
  SELECT RAISE(ABORT, 'last active catalog owner');
END
"""


def upgrade() -> None:
    with op.batch_alter_table("principals") as batch:
        batch.add_column(sa.Column("catalog_role", sa.String(length=32), nullable=True))
        batch.create_check_constraint(
            "ck_principals_catalog_role",
            "catalog_role IS NULL OR catalog_role = 'catalog_owner'",
        )
        batch.create_index(
            "ix_principals_catalog_role",
            ["catalog_role"],
        )
    _restore_last_admin_triggers()
    op.execute(_LAST_CATALOG_OWNER_UPDATE_TRIGGER)
    op.execute(_LAST_CATALOG_OWNER_DELETE_TRIGGER)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_catalog_owner_delete")
    op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_catalog_owner_update")
    with op.batch_alter_table("principals") as batch:
        batch.drop_index("ix_principals_catalog_role")
        batch.drop_constraint("ck_principals_catalog_role", type_="check")
        batch.drop_column("catalog_role")
    _restore_last_admin_triggers()


def _restore_last_admin_triggers() -> None:
    op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_admin_update")
    op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_admin_delete")
    op.execute(_LAST_ADMIN_UPDATE_TRIGGER)
    op.execute(_LAST_ADMIN_DELETE_TRIGGER)
