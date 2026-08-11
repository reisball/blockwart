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

_LAST_CATALOG_OWNER_UPDATE_TRIGGER_SQLITE = """
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

_LAST_CATALOG_OWNER_DELETE_TRIGGER_SQLITE = """
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

_CATALOG_OWNER_COUNTER_TRIGGERS_SQLITE = (
    """
    CREATE TRIGGER ck_principals_active_catalog_owner_counter_insert
    AFTER INSERT ON principals
    WHEN NEW.active = 1 AND NEW.catalog_role = 'catalog_owner'
    BEGIN
      UPDATE principal_invariant_counts SET active_count = active_count + 1
      WHERE invariant = 'catalog_owner';
    END
    """,
    """
    CREATE TRIGGER ck_principals_active_catalog_owner_counter_update
    AFTER UPDATE OF active, catalog_role ON principals
    WHEN (CASE WHEN OLD.active = 1 AND OLD.catalog_role = 'catalog_owner' THEN 1 ELSE 0 END)
      <> (CASE WHEN NEW.active = 1 AND NEW.catalog_role = 'catalog_owner' THEN 1 ELSE 0 END)
    BEGIN
      UPDATE principal_invariant_counts
      SET active_count = active_count + CASE
        WHEN NEW.active = 1 AND NEW.catalog_role = 'catalog_owner' THEN 1 ELSE -1 END
      WHERE invariant = 'catalog_owner';
    END
    """,
    """
    CREATE TRIGGER ck_principals_active_catalog_owner_counter_delete
    AFTER DELETE ON principals
    WHEN OLD.active = 1 AND OLD.catalog_role = 'catalog_owner'
    BEGIN
      UPDATE principal_invariant_counts SET active_count = active_count - 1
      WHERE invariant = 'catalog_owner';
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

_LAST_CATALOG_OWNER_UPDATE_TRIGGER_PG = """
CREATE TRIGGER ck_principals_last_active_catalog_owner_update
BEFORE UPDATE OF active, catalog_role ON principals
FOR EACH ROW
WHEN (OLD.active = true AND OLD.catalog_role = 'catalog_owner'
  AND (NEW.active = false OR NEW.catalog_role IS NULL OR NEW.catalog_role <> 'catalog_owner'))
EXECUTE FUNCTION blockwart_check_last_active_catalog_owner()
"""

_LAST_CATALOG_OWNER_DELETE_TRIGGER_PG = """
CREATE TRIGGER ck_principals_last_active_catalog_owner_delete
BEFORE DELETE ON principals
FOR EACH ROW
WHEN (OLD.active = true AND OLD.catalog_role = 'catalog_owner')
EXECUTE FUNCTION blockwart_check_last_active_catalog_owner()
"""

_CATALOG_OWNER_COUNTER_TRIGGER_PG = """
CREATE TRIGGER ck_principals_active_catalog_owner_counter
AFTER INSERT OR UPDATE ON principals
FOR EACH ROW
EXECUTE FUNCTION blockwart_increment_active_catalog_owner_count()
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
    op.execute(
        "INSERT INTO principal_invariant_counts (invariant, active_count) "
        "SELECT 'catalog_owner', COUNT(*) FROM principals "
        "WHERE active = true AND catalog_role = 'catalog_owner'"
    )
    _restore_last_admin_triggers()
    _bind = op.get_bind()
    if _bind.dialect.name == "sqlite":
        op.execute(_LAST_CATALOG_OWNER_UPDATE_TRIGGER_SQLITE)
        op.execute(_LAST_CATALOG_OWNER_DELETE_TRIGGER_SQLITE)
        for statement in _CATALOG_OWNER_COUNTER_TRIGGERS_SQLITE:
            op.execute(statement)
    else:
        _create_postgresql_catalog_owner_functions()
        op.execute(_LAST_CATALOG_OWNER_UPDATE_TRIGGER_PG)
        op.execute(_LAST_CATALOG_OWNER_DELETE_TRIGGER_PG)
        op.execute(_CATALOG_OWNER_COUNTER_TRIGGER_PG)


def downgrade() -> None:
    _bind = op.get_bind()
    if _bind.dialect.name == "sqlite":
        for trigger in (
            "ck_principals_active_catalog_owner_counter_insert",
            "ck_principals_active_catalog_owner_counter_update",
            "ck_principals_active_catalog_owner_counter_delete",
        ):
            op.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_catalog_owner_delete")
        op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_catalog_owner_update")
    else:
        op.execute("DROP TRIGGER IF EXISTS ck_principals_active_catalog_owner_counter ON principals")  # noqa: E501
        op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_catalog_owner_delete ON principals")  # noqa: E501
        op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_catalog_owner_update ON principals")  # noqa: E501
        op.execute("DROP FUNCTION IF EXISTS blockwart_increment_active_catalog_owner_count()")  # noqa: E501
        op.execute("DROP FUNCTION IF EXISTS blockwart_check_last_active_catalog_owner()")
    op.execute(
        "DELETE FROM principal_invariant_counts WHERE invariant = 'catalog_owner'"
    )
    with op.batch_alter_table("principals") as batch:
        batch.drop_index("ix_principals_catalog_role")
        batch.drop_constraint("ck_principals_catalog_role", type_="check")
        batch.drop_column("catalog_role")
    _restore_last_admin_triggers()


def _restore_last_admin_triggers() -> None:
    _bind = op.get_bind()
    if _bind.dialect.name == "sqlite":
        for trigger in (
            "ck_principals_active_admin_counter_insert",
            "ck_principals_active_admin_counter_update",
            "ck_principals_active_admin_counter_delete",
        ):
            op.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_admin_update")
        op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_admin_delete")
        op.execute(_LAST_ADMIN_UPDATE_TRIGGER_SQLITE)
        op.execute(_LAST_ADMIN_DELETE_TRIGGER_SQLITE)
        for statement in _ADMIN_COUNTER_TRIGGERS_SQLITE:
            op.execute(statement)
    else:
        op.execute("DROP TRIGGER IF EXISTS ck_principals_active_admin_counter ON principals")  # noqa: E501
        op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_admin_update ON principals")
        op.execute("DROP TRIGGER IF EXISTS ck_principals_last_active_admin_delete ON principals")
        op.execute(
            "UPDATE principal_invariant_counts SET active_count = ("
            "SELECT COUNT(*) FROM principals "
            "WHERE active = true AND platform_role = 'admin') "
            "WHERE invariant = 'platform_admin'"
        )
        _create_postgresql_admin_functions()
        op.execute(_LAST_ADMIN_UPDATE_TRIGGER_PG)
        op.execute(_LAST_ADMIN_DELETE_TRIGGER_PG)
        op.execute(_ADMIN_COUNTER_TRIGGER_PG)


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


def _create_postgresql_catalog_owner_functions() -> None:
    op.execute(
        "CREATE OR REPLACE FUNCTION blockwart_check_last_active_catalog_owner() "
        "RETURNS TRIGGER AS $$ "
        "DECLARE remaining integer; "
        "BEGIN "
        "UPDATE principal_invariant_counts SET active_count = active_count - 1 "
        "WHERE invariant = 'catalog_owner' AND active_count > 1 "
        "RETURNING active_count INTO remaining; "
        "IF remaining IS NULL THEN "
        "RAISE EXCEPTION 'last active catalog owner'; "
        "END IF; "
        "IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF; "
        "END; $$ LANGUAGE plpgsql"
    )
    op.execute(
        "CREATE OR REPLACE FUNCTION blockwart_increment_active_catalog_owner_count() "
        "RETURNS TRIGGER AS $$ "
        "BEGIN "
        "IF NEW.active = true AND NEW.catalog_role = 'catalog_owner' THEN "
        "IF TG_OP = 'INSERT' THEN "
        "UPDATE principal_invariant_counts SET active_count = active_count + 1 "
        "WHERE invariant = 'catalog_owner'; "
        "ELSIF OLD.active IS NOT TRUE "
        "OR OLD.catalog_role IS DISTINCT FROM 'catalog_owner' THEN "
        "UPDATE principal_invariant_counts SET active_count = active_count + 1 "
        "WHERE invariant = 'catalog_owner'; "
        "END IF; "
        "END IF; "
        "RETURN NEW; "
        "END; $$ LANGUAGE plpgsql"
    )
