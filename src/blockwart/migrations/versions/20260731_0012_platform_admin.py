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

_ADMIN_COUNTER_TRIGGERS_SQLITE = (
    """
    CREATE TRIGGER ck_principals_active_admin_counter_insert
    AFTER INSERT ON principals
    WHEN NEW.active = 1 AND NEW.platform_role = 'admin'
    BEGIN
      UPDATE principal_invariant_counts SET active_count = active_count + 1
      WHERE invariant = 'platform_admin';
    END
    """,
    """
    CREATE TRIGGER ck_principals_active_admin_counter_update
    AFTER UPDATE OF active, platform_role ON principals
    WHEN (CASE WHEN OLD.active = 1 AND OLD.platform_role = 'admin' THEN 1 ELSE 0 END)
      <> (CASE WHEN NEW.active = 1 AND NEW.platform_role = 'admin' THEN 1 ELSE 0 END)
    BEGIN
      UPDATE principal_invariant_counts
      SET active_count = active_count + CASE
        WHEN NEW.active = 1 AND NEW.platform_role = 'admin' THEN 1 ELSE -1 END
      WHERE invariant = 'platform_admin';
    END
    """,
    """
    CREATE TRIGGER ck_principals_active_admin_counter_delete
    AFTER DELETE ON principals
    WHEN OLD.active = 1 AND OLD.platform_role = 'admin'
    BEGIN
      UPDATE principal_invariant_counts SET active_count = active_count - 1
      WHERE invariant = 'platform_admin';
    END
    """,
)

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

_ADMIN_COUNTER_TRIGGER_PG = """
CREATE TRIGGER ck_principals_active_admin_counter
AFTER INSERT OR UPDATE ON principals
FOR EACH ROW
EXECUTE FUNCTION blockwart_increment_active_admin_count()
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
    op.create_table(
        "principal_invariant_counts",
        sa.Column("invariant", sa.String(length=32), nullable=False),
        sa.Column("active_count", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "active_count >= 0",
            name="ck_principal_invariant_counts_nonnegative",
        ),
        sa.CheckConstraint(
            "invariant IN ('platform_admin','catalog_owner')",
            name="ck_principal_invariant_counts_known",
        ),
        sa.PrimaryKeyConstraint("invariant"),
    )
    op.execute(
        "INSERT INTO principal_invariant_counts (invariant, active_count) "
        "SELECT 'platform_admin', COUNT(*) FROM principals "
        "WHERE active = true AND platform_role = 'admin'"
    )
    _bind = op.get_bind()
    if _bind.dialect.name == "sqlite":
        op.execute(_LAST_ADMIN_UPDATE_TRIGGER_SQLITE)
        op.execute(_LAST_ADMIN_DELETE_TRIGGER_SQLITE)
        for statement in _ADMIN_COUNTER_TRIGGERS_SQLITE:
            op.execute(statement)
    else:
        _create_postgresql_admin_functions()
        op.execute(_LAST_ADMIN_UPDATE_TRIGGER_PG)
        op.execute(_LAST_ADMIN_DELETE_TRIGGER_PG)
        op.execute(_ADMIN_COUNTER_TRIGGER_PG)


def downgrade() -> None:
    _bind = op.get_bind()
    if _bind.dialect.name == "sqlite":
        for trigger in (
            "ck_principals_active_admin_counter_insert",
            "ck_principals_active_admin_counter_update",
            "ck_principals_active_admin_counter_delete",
        ):
            op.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_admin_delete")
        op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_admin_update")
    else:
        op.execute("DROP TRIGGER IF EXISTS ck_principals_active_admin_counter ON principals")  # noqa: E501
        op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_admin_delete ON principals")
        op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_admin_update ON principals")
        op.execute("DROP FUNCTION IF EXISTS blockwart_increment_active_admin_count()")
        op.execute("DROP FUNCTION IF EXISTS blockwart_check_last_active_admin()")
    op.drop_table("principal_invariant_counts")
    with op.batch_alter_table("principals") as batch:
        batch.drop_index("ix_principals_platform_role")
        batch.drop_constraint("ck_principals_revision_positive", type_="check")
        batch.drop_constraint("ck_principals_platform_role", type_="check")
        batch.drop_column("revision")
        batch.drop_column("platform_role")


def _create_postgresql_admin_functions() -> None:
    op.execute(
        "CREATE OR REPLACE FUNCTION blockwart_check_last_active_admin() "
        "RETURNS TRIGGER AS $$ "
        "DECLARE remaining integer; "
        "BEGIN "
        "UPDATE principal_invariant_counts SET active_count = active_count - 1 "
        "WHERE invariant = 'platform_admin' AND active_count > 1 "
        "RETURNING active_count INTO remaining; "
        "IF remaining IS NULL THEN "
        "RAISE EXCEPTION 'last active platform admin'; "
        "END IF; "
        "IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF; "
        "END; $$ LANGUAGE plpgsql"
    )
    op.execute(
        "CREATE OR REPLACE FUNCTION blockwart_increment_active_admin_count() "
        "RETURNS TRIGGER AS $$ "
        "BEGIN "
        "IF NEW.active = true AND NEW.platform_role = 'admin' THEN "
        "IF TG_OP = 'INSERT' THEN "
        "UPDATE principal_invariant_counts SET active_count = active_count + 1 "
        "WHERE invariant = 'platform_admin'; "
        "ELSIF OLD.active IS NOT TRUE "
        "OR OLD.platform_role IS DISTINCT FROM 'admin' THEN "
        "UPDATE principal_invariant_counts SET active_count = active_count + 1 "
        "WHERE invariant = 'platform_admin'; "
        "END IF; "
        "END IF; "
        "RETURN NEW; "
        "END; $$ LANGUAGE plpgsql"
    )
