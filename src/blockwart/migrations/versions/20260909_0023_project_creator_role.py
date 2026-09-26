"""allow the narrow global catalog role ``project_creator``

Revision ID: 20260909_0023
Revises: 20260909_0022

The migration only expands the existing catalog-role value constraint by the
new narrow ``project_creator`` role. It assigns no role, writes no grant, and
rewrites no existing row: every ``catalog_owner`` and ``catalog_viewer``
assignment keeps its exact stored value and its exact meaning.

``project_creator`` carries no catalog-wide object permission and no
last-active-holder invariant, so no counter row, counter trigger, or guard
trigger is added for it. The four established last-active guards and the six
counter triggers stay bound to ``platform_admin`` and ``catalog_owner`` only,
and are recreated verbatim after the SQLite table rebuild that replaces the
check constraint drops them.

A downgrade fails closed while any principal still carries ``project_creator``,
because the preceding schema cannot represent that value without silently
dropping the root-creation authority it expresses.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260909_0023"
down_revision: str | Sequence[str] | None = "20260909_0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OWNER_VIEWER_CHECK = (
    "catalog_role IS NULL OR catalog_role IN ('catalog_owner','catalog_viewer')"
)
_OWNER_VIEWER_CREATOR_CHECK = (
    "catalog_role IS NULL OR "
    "catalog_role IN ('catalog_owner','catalog_viewer','project_creator')"
)

# SQLite rebuilds ``principals`` to replace its check constraint and therefore
# drops all table triggers. These statements are the established platform-admin
# and catalog-owner invariant triggers, recreated without semantic changes.
_SQLITE_PRINCIPAL_INVARIANT_DDL = (
    """
    CREATE TRIGGER ck_principals_last_active_admin_update
    BEFORE UPDATE OF active, platform_role ON principals
    WHEN OLD.active = 1 AND OLD.platform_role = 'admin'
      AND (NEW.active = 0 OR NEW.platform_role IS NULL OR NEW.platform_role <> 'admin')
      AND NOT EXISTS (
        SELECT 1 FROM principals
        WHERE id <> OLD.id AND active = 1 AND platform_role = 'admin'
      )
    BEGIN SELECT RAISE(ABORT, 'last active platform admin'); END
    """,
    """
    CREATE TRIGGER ck_principals_last_active_admin_delete
    BEFORE DELETE ON principals
    WHEN OLD.active = 1 AND OLD.platform_role = 'admin'
      AND NOT EXISTS (
        SELECT 1 FROM principals
        WHERE id <> OLD.id AND active = 1 AND platform_role = 'admin'
      )
    BEGIN SELECT RAISE(ABORT, 'last active platform admin'); END
    """,
    """
    CREATE TRIGGER ck_principals_last_active_catalog_owner_update
    BEFORE UPDATE OF active, catalog_role ON principals
    WHEN OLD.active = 1 AND OLD.catalog_role = 'catalog_owner'
      AND (NEW.active = 0 OR NEW.catalog_role IS NULL OR NEW.catalog_role <> 'catalog_owner')
      AND NOT EXISTS (
        SELECT 1 FROM principals
        WHERE id <> OLD.id AND active = 1 AND catalog_role = 'catalog_owner'
      )
    BEGIN SELECT RAISE(ABORT, 'last active catalog owner'); END
    """,
    """
    CREATE TRIGGER ck_principals_last_active_catalog_owner_delete
    BEFORE DELETE ON principals
    WHEN OLD.active = 1 AND OLD.catalog_role = 'catalog_owner'
      AND NOT EXISTS (
        SELECT 1 FROM principals
        WHERE id <> OLD.id AND active = 1 AND catalog_role = 'catalog_owner'
      )
    BEGIN SELECT RAISE(ABORT, 'last active catalog owner'); END
    """,
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

_SQLITE_TRIGGER_NAMES = (
    "ck_principals_last_active_admin_update",
    "ck_principals_last_active_admin_delete",
    "ck_principals_last_active_catalog_owner_update",
    "ck_principals_last_active_catalog_owner_delete",
    "ck_principals_active_admin_counter_insert",
    "ck_principals_active_admin_counter_update",
    "ck_principals_active_admin_counter_delete",
    "ck_principals_active_catalog_owner_counter_insert",
    "ck_principals_active_catalog_owner_counter_update",
    "ck_principals_active_catalog_owner_counter_delete",
)


def upgrade() -> None:
    _replace_catalog_role_check(_OWNER_VIEWER_CREATOR_CHECK)


def downgrade() -> None:
    bind = op.get_bind()
    creator_count = bind.scalar(
        sa.text(
            "SELECT COUNT(*) FROM principals WHERE catalog_role = 'project_creator'"
        )
    )
    if int(creator_count or 0) != 0:
        raise RuntimeError(
            "Project-creator roles must be explicitly removed before downgrade; "
            "restore the paired pre-migration backup if rollback is required"
        )
    _replace_catalog_role_check(_OWNER_VIEWER_CHECK)


def _replace_catalog_role_check(expression: str) -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        for trigger_name in _SQLITE_TRIGGER_NAMES:
            op.execute(f"DROP TRIGGER IF EXISTS {trigger_name}")
        with op.batch_alter_table("principals", recreate="always") as batch:
            batch.drop_constraint("ck_principals_catalog_role", type_="check")
            batch.create_check_constraint("ck_principals_catalog_role", expression)
        for statement in _SQLITE_PRINCIPAL_INVARIANT_DDL:
            op.execute(statement)
        return
    op.drop_constraint("ck_principals_catalog_role", "principals", type_="check")
    op.create_check_constraint(
        "ck_principals_catalog_role",
        "principals",
        expression,
    )
