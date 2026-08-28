"""allow the explicit global catalog-viewer role

Revision ID: 20260822_0019
Revises: 20260818_0018

The migration only expands the existing catalog-role value constraint. It does
not assign a role, create a grant, or otherwise mutate principal authority. A
downgrade fails closed while any principal still carries ``catalog_viewer``
because the preceding schema cannot represent that value without data loss.

It additionally repairs one historical schema before touching the constraint:
an installation upgraded to 20260818_0018 before revision 20260731_0012 was
retroactively corrected carries the last-active-admin and last-active-catalog-
owner guards but neither ``principal_invariant_counts`` nor the six counter
triggers. The counter triggers recreated here reference that table, so the next
SQLite table rebuild would fail while it is absent. See
``_ensure_principal_invariant_counts``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260822_0019"
down_revision: str | Sequence[str] | None = "20260818_0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INVARIANT_SOURCES = (
    ("platform_admin", "platform_role = 'admin'"),
    ("catalog_owner", "catalog_role = 'catalog_owner'"),
)

_OWNER_ONLY_CHECK = "catalog_role IS NULL OR catalog_role = 'catalog_owner'"
_OWNER_VIEWER_CHECK = (
    "catalog_role IS NULL OR catalog_role IN ('catalog_owner','catalog_viewer')"
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
    _replace_catalog_role_check(_OWNER_VIEWER_CHECK)


def downgrade() -> None:
    bind = op.get_bind()
    viewer_count = bind.scalar(
        sa.text(
            "SELECT COUNT(*) FROM principals WHERE catalog_role = 'catalog_viewer'"
        )
    )
    if int(viewer_count or 0) != 0:
        raise RuntimeError(
            "Catalog viewer roles must be explicitly removed before downgrade; "
            "restore the paired pre-migration backup if rollback is required"
        )
    _replace_catalog_role_check(_OWNER_ONLY_CHECK)


def _ensure_principal_invariant_counts() -> None:
    """Restore ``principal_invariant_counts`` when the deployed schema lacks it.

    The table and its counter triggers were added to revision 20260731_0012
    retroactively, so a database upgraded to 20260818_0018 before that can be
    missing both while still carrying the four last-active guard triggers. Every
    absent row is reconstructed by counting the principals that actually hold the
    role, never a guessed value. A database that already has the table keeps its
    trigger-maintained counters untouched.
    """
    bind = op.get_bind()
    if not sa.inspect(bind).has_table("principal_invariant_counts"):
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
    present = {
        str(row[0])
        for row in bind.execute(
            sa.text("SELECT invariant FROM principal_invariant_counts")
        )
    }
    for invariant, predicate in _INVARIANT_SOURCES:
        if invariant in present:
            continue
        op.execute(
            "INSERT INTO principal_invariant_counts (invariant, active_count) "
            f"SELECT '{invariant}', COUNT(*) FROM principals "
            f"WHERE active = true AND {predicate}"
        )


def _replace_catalog_role_check(expression: str) -> None:
    _ensure_principal_invariant_counts()
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
