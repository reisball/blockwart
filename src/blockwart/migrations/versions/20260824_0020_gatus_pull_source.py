"""add the gatus pull provider and its acquisition instant

Revision ID: 20260824_0020
Revises: 20260822_0019

Three additive schema changes support the Gatus pull adapter (#177):

1. the CHECK constraints on ``service_observations.provider`` and
   ``service_check_leases.provider`` accept ``'gatus'`` beside
   ``'builtin_http'``.  The gatus provider is a **pull** adapter — the
   scheduler reads the current status data of a deployment-bound source — so
   it creates lease rows exactly like the built-in probe and both constraints
   must be widened;
2. the CHECK constraint on ``service_observations.error_code`` accepts the
   bounded pull-source acquisition codes.  None of them claims the monitored
   service is down; they say this deployment could not obtain usable evidence;
3. ``service_observations.last_received_at`` records the instant this
   deployment acquired evidence, separately from ``last_checked_at``, which
   stays the instant the evidence is *about*.  It is nullable and back-filled
   for nothing, so every existing row stays byte-for-byte unchanged.

No data is migrated, no column changes type, and no existing row is altered.

SQLite does not support ``ALTER TABLE … DROP CONSTRAINT``; we use
``batch_alter_table(recreate="always")`` on that dialect.

The downgrade narrows both vocabularies again.  It refuses to run while any
row still uses the widened vocabulary rather than deleting observations, so a
rollback can never silently discard monitoring history.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260824_0020"
down_revision: str | Sequence[str] | None = "20260822_0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_BUILTIN_PROVIDERS = "'builtin_http'"
_PROVIDERS = "'builtin_http','gatus'"
_BUILTIN_ERROR_CODES = (
    "'connect_failed','dns_failed','http_client_error','http_server_error',"
    "'invalid_target','policy_denied','probe_failed','redirect_not_supported',"
    "'response_too_large','timeout','tls_failed'"
)
_ERROR_CODES = (
    f"{_BUILTIN_ERROR_CODES},"
    "'invalid_observation_time','mapping_ambiguous','mapping_missing',"
    "'source_unconfigured','source_unreadable'"
)
_PULL_ERROR_CODES = (
    "invalid_observation_time",
    "mapping_ambiguous",
    "mapping_missing",
    "source_unconfigured",
    "source_unreadable",
)


def _rebuild_check(table: str, constraint: str, condition: str) -> None:
    """Drop and recreate one named CHECK constraint on ``table``.

    Uses batch_alter_table on SQLite (which lacks DROP CONSTRAINT) and direct
    DDL on PostgreSQL.

    Args:
        table: The target table name.
        constraint: The constraint name to rebuild.
        condition: The new CHECK condition SQL.
    """
    if op.get_context().dialect.name == "sqlite":
        with op.batch_alter_table(table, recreate="always") as batch_op:
            batch_op.drop_constraint(constraint, type_="check")
            batch_op.create_check_constraint(constraint, condition)
    else:
        op.drop_constraint(constraint, table, type_="check")
        op.create_check_constraint(constraint, table, condition)


def _reject_rows(statement: str, message: str) -> None:
    """Abort the downgrade while rows still need the widened vocabulary."""
    remaining = op.get_bind().execute(sa.text(statement)).scalar_one()
    if remaining:
        raise RuntimeError(message)


def upgrade() -> None:
    _rebuild_check(
        "service_observations",
        "ck_service_observations_provider",
        f"provider IN ({_PROVIDERS})",
    )
    _rebuild_check(
        "service_observations",
        "ck_service_observations_error_code",
        f"error_code IS NULL OR error_code IN ({_ERROR_CODES})",
    )
    _rebuild_check(
        "service_check_leases",
        "ck_service_check_leases_provider",
        f"provider IN ({_PROVIDERS})",
    )
    op.add_column(
        "service_observations",
        sa.Column("last_received_at", sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    codes = ",".join(f"'{code}'" for code in _PULL_ERROR_CODES)
    _reject_rows(
        "SELECT COUNT(*) FROM service_check_leases WHERE provider = 'gatus'",
        "refusing to downgrade while gatus check leases exist; remove the "
        "gatus monitoring configuration and let the scheduler reconcile first",
    )
    _reject_rows(
        "SELECT COUNT(*) FROM service_observations WHERE provider = 'gatus'",
        "refusing to downgrade while gatus observations exist; remove the "
        "gatus monitoring configuration and let the scheduler reconcile first",
    )
    _reject_rows(
        f"SELECT COUNT(*) FROM service_observations WHERE error_code IN ({codes})",
        "refusing to downgrade while pull-source error codes are stored; "
        "clear the affected observations first",
    )
    op.drop_column("service_observations", "last_received_at")
    _rebuild_check(
        "service_check_leases",
        "ck_service_check_leases_provider",
        f"provider IN ({_BUILTIN_PROVIDERS})",
    )
    _rebuild_check(
        "service_observations",
        "ck_service_observations_error_code",
        f"error_code IS NULL OR error_code IN ({_BUILTIN_ERROR_CODES})",
    )
    _rebuild_check(
        "service_observations",
        "ck_service_observations_provider",
        f"provider IN ({_BUILTIN_PROVIDERS})",
    )
