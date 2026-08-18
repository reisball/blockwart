"""add canonical service observation and check lease tables

Revision ID: 20260818_0017
Revises: 20260811_0016

The revision is purely additive. It creates two new tables and touches no
existing table, column, index, trigger, or row, so an upgrade from a populated
pre-#135 database preserves every catalog object, relationship, comment,
provenance header, grant, principal, and source-coverage row byte-for-byte.

No monitoring configuration is written by this migration. Absent
``data.monitoring`` is exactly ``enabled=false``, so an upgraded catalog stays
unmonitored until an operator enables a service deliberately.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260818_0017"
down_revision: str | Sequence[str] | None = "20260811_0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PROVIDERS = "'builtin_http'"
_STATES = "'unknown','healthy','down','check_error'"
_ERROR_CODES = (
    "'connect_failed','dns_failed','http_client_error','http_server_error',"
    "'invalid_target','policy_denied','probe_failed','redirect_not_supported',"
    "'response_too_large','timeout','tls_failed'"
)


def upgrade() -> None:
    # No foreign key to catalog_objects: observation rows are bound to a
    # concrete object instance, and a deleted object must not cascade into the
    # scheduling path. Stale rows are pruned explicitly by the scheduler.
    op.create_table(
        "service_observations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("object_id", sa.String(length=128), nullable=False),
        sa.Column("object_instance_id", sa.String(length=32), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("error_code", sa.String(length=32), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(), nullable=True),
        sa.Column("last_success_at", sa.DateTime(), nullable=True),
        sa.Column("next_due_at", sa.DateTime(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            f"provider IN ({_PROVIDERS})",
            name="ck_service_observations_provider",
        ),
        sa.CheckConstraint(
            f"state IN ({_STATES})",
            name="ck_service_observations_state",
        ),
        sa.CheckConstraint(
            f"error_code IS NULL OR error_code IN ({_ERROR_CODES})",
            name="ck_service_observations_error_code",
        ),
        sa.CheckConstraint(
            "http_status IS NULL OR (http_status >= 100 AND http_status <= 599)",
            name="ck_service_observations_http_status",
        ),
        sa.CheckConstraint(
            "latency_ms IS NULL OR latency_ms >= 0",
            name="ck_service_observations_latency",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "object_id",
            "object_instance_id",
            "provider",
            name="uq_service_observations_identity",
        ),
    )
    op.create_index(
        "ix_service_observations_object",
        "service_observations",
        ["object_id", "object_instance_id"],
    )

    op.create_table(
        "service_check_leases",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("object_id", sa.String(length=128), nullable=False),
        sa.Column("object_instance_id", sa.String(length=32), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("due_at", sa.DateTime(), nullable=False),
        sa.Column("lease_owner", sa.String(length=64), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            f"provider IN ({_PROVIDERS})",
            name="ck_service_check_leases_provider",
        ),
        sa.CheckConstraint(
            "(lease_owner IS NULL AND lease_expires_at IS NULL) OR "
            "(lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)",
            name="ck_service_check_leases_lease_pair",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "object_id",
            "object_instance_id",
            name="uq_service_check_leases_identity",
        ),
    )
    op.create_index(
        "ix_service_check_leases_due",
        "service_check_leases",
        ["due_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_service_check_leases_due", table_name="service_check_leases")
    op.drop_table("service_check_leases")
    op.drop_index("ix_service_observations_object", table_name="service_observations")
    op.drop_table("service_observations")
