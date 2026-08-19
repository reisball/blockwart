"""allow gatus as monitoring provider in CHECK constraints

Revision ID: 20260819_0019
Revises: 20260818_0018

The CHECK constraints on ``service_observations.provider`` and
``service_check_leases.provider`` are rebuilt to accept ``'gatus'``
beside ``'builtin_http'``.  This is a constraint widening — no data is
migrated, no column changes type, and no existing row is altered.

The gatus provider is push-based and never creates lease rows, so only
the observation table will ever store ``provider='gatus'`` in practice.
The lease constraint is widened for symmetry and forward safety.

SQLite does not support ``ALTER TABLE … DROP CONSTRAINT``; we use
``batch_alter_table(recreate="always")`` on that dialect.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "20260819_0019"
down_revision: str | Sequence[str] | None = "20260818_0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PROVIDERS = "'builtin_http','gatus'"


def _widen_provider_constraint(table: str, providers: str) -> None:
    """Drop and recreate the ``ck_{table}_provider`` CHECK constraint.

    Uses batch_alter_table on SQLite (which lacks DROP CONSTRAINT) and
    direct DDL on PostgreSQL.

    Args:
        table: The target table name.
        providers: The SQL literal list for the CHECK, e.g. ``"'a','b'"``.
    """
    dialect = op.get_context().dialect.name
    constraint = f"ck_{table}_provider"
    if dialect == "sqlite":
        with op.batch_alter_table(table, recreate="always") as batch_op:
            batch_op.drop_constraint(constraint, type_="check")
            batch_op.create_check_constraint(constraint, f"provider IN ({providers})")
    else:
        op.drop_constraint(constraint, table, type_="check")
        op.create_check_constraint(constraint, table, f"provider IN ({providers})")


def upgrade() -> None:
    _widen_provider_constraint("service_observations", _PROVIDERS)
    _widen_provider_constraint("service_check_leases", _PROVIDERS)


def downgrade() -> None:
    _widen_provider_constraint("service_check_leases", "'builtin_http'")
    _widen_provider_constraint("service_observations", "'builtin_http'")
