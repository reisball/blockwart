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
    op.execute(_LAST_ADMIN_UPDATE_TRIGGER)
    op.execute(_LAST_ADMIN_DELETE_TRIGGER)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_admin_delete")
    op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_admin_update")
    with op.batch_alter_table("principals") as batch:
        batch.drop_index("ix_principals_platform_role")
        batch.drop_constraint("ck_principals_revision_positive", type_="check")
        batch.drop_constraint("ck_principals_platform_role", type_="check")
        batch.drop_column("revision")
        batch.drop_column("platform_role")
