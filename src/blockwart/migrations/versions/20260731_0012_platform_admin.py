"""add platform administration to principals

Revision ID: 20260731_0012
Revises: 20260731_0011
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260731_0012"
down_revision: str | Sequence[str] | None = "20260731_0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_LAST_ADMIN_UPDATE_TRIGGER_SQLITE = """
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

_LAST_ADMIN_DELETE_TRIGGER_SQLITE = """
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

_LAST_ADMIN_UPDATE_TRIGGER_PG = """
CREATE TRIGGER ck_principals_last_active_admin_update
BEFORE UPDATE OF active, platform_role ON principals
FOR EACH ROW
WHEN (OLD.active = true AND OLD.platform_role = 'admin'
  AND (NEW.active = false OR NEW.platform_role IS NULL OR NEW.platform_role <> 'admin'))
EXECUTE FUNCTION blockwart_check_last_active_admin()
"""

_LAST_ADMIN_DELETE_TRIGGER_PG = """
CREATE TRIGGER ck_principals_last_active_admin_delete
BEFORE DELETE ON principals
FOR EACH ROW
WHEN (OLD.active = true AND OLD.platform_role = 'admin')
EXECUTE FUNCTION blockwart_check_last_active_admin()
"""


def upgrade() -> None:
    with op.batch_alter_table("principals") as batch:
        batch.add_column(sa.Column("platform_role", sa.String(length=32), nullable=True))
        batch.add_column(
            sa.Column(
                "revision",
                sa.Integer(),
                server_default=sa.text("1"),
                nullable=False,
            )
        )
        batch.create_check_constraint(
            "ck_principals_platform_role",
            "platform_role IS NULL OR platform_role = 'admin'",
        )
        batch.create_check_constraint(
            "ck_principals_revision_positive",
            "revision >= 1",
        )
        batch.create_index(
            "ix_principals_platform_role",
            ["platform_role"],
        )
    _bind = op.get_bind()
    if _bind.dialect.name == "sqlite":
        op.execute(_LAST_ADMIN_UPDATE_TRIGGER_SQLITE)
        op.execute(_LAST_ADMIN_DELETE_TRIGGER_SQLITE)
    else:
        op.execute("CREATE OR REPLACE FUNCTION blockwart_check_last_active_admin() RETURNS TRIGGER AS $$ BEGIN IF NOT EXISTS (SELECT 1 FROM principals WHERE id <> OLD.id AND active = true AND platform_role = 'admin') THEN RAISE EXCEPTION 'last active platform admin'; END IF; IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF; END; $$ LANGUAGE plpgsql")
        op.execute(_LAST_ADMIN_UPDATE_TRIGGER_PG)
        op.execute(_LAST_ADMIN_DELETE_TRIGGER_PG)


def downgrade() -> None:
    _bind = op.get_bind()
    if _bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_admin_delete")
        op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_admin_update")
    else:
        op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_admin_delete ON principals")
        op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_admin_update ON principals")
    with op.batch_alter_table("principals") as batch:
        batch.drop_index("ix_principals_platform_role")
        batch.drop_constraint("ck_principals_revision_positive", type_="check")
        batch.drop_constraint("ck_principals_platform_role", type_="check")
        batch.drop_column("revision")
        batch.drop_column("platform_role")
