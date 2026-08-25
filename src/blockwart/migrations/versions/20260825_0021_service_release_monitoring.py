"""add the public release observation and release check lease tables

Revision ID: 20260825_0021
Revises: 20260824_0020

The revision is purely additive.  It creates two new tables and touches no
existing table, column, index, constraint, trigger, or row, so an upgrade from
a populated pre-#105 database preserves every catalog object, relationship,
comment, provenance header, grant, principal, source-coverage row, health
observation, and health check lease byte-for-byte.

No release-monitoring configuration is written by this migration.  Absent
``data.release_monitoring`` is exactly ``enabled=false``, so an upgraded
catalog performs no outbound release check until an operator both enables the
feature in the deployment and enables one concrete service deliberately.

Release state is stored apart from ``service_observations`` on purpose.  A
health observation and a release observation answer different questions, and
separate tables are what keeps "an update is available" from ever becoming an
availability claim.

The downgrade drops exactly the two tables this revision created.  It is
therefore a clean rollback of the schema: no pre-existing structure is
restored, altered, or re-derived, and nothing outside release monitoring can
lose data.  Only the release observations and their scheduling state — all of
which are re-derivable by checking again — are removed.  Before a live
rollback, stop Blockwart and restore the verified pre-upgrade database with the
matching previous image according to the deployment recovery contract.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260825_0021"
down_revision: str | Sequence[str] | None = "20260824_0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PROVIDERS = "'github_releases'"
_ERROR_CODES = (
    "'connect_failed','dns_failed','http_client_error','http_server_error',"
    "'invalid_release_version','invalid_target','not_a_stable_release',"
    "'not_found','policy_denied','provider_failed','rate_limited',"
    "'redirect_not_supported','response_too_large','timeout','tls_failed',"
    "'unreadable_release'"
)


def upgrade() -> None:
    # No foreign key to catalog_objects: observation rows are bound to a
    # concrete object instance, and a deleted object must not cascade into the
    # scheduling path. Stale rows are pruned explicitly by the scheduler.
    op.create_table(
        "service_release_observations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("object_id", sa.String(length=128), nullable=False),
        sa.Column("object_instance_id", sa.String(length=32), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("target_key", sa.String(length=64), nullable=False),
        sa.Column("latest_tag", sa.String(length=128), nullable=True),
        sa.Column("latest_version", sa.String(length=64), nullable=True),
        sa.Column("released_at", sa.DateTime(), nullable=True),
        sa.Column("release_etag", sa.String(length=128), nullable=True),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("error_code", sa.String(length=32), nullable=True),
        sa.Column(
            "consecutive_failures",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
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
            name="ck_service_release_observations_provider",
        ),
        sa.CheckConstraint(
            f"error_code IS NULL OR error_code IN ({_ERROR_CODES})",
            name="ck_service_release_observations_error_code",
        ),
        sa.CheckConstraint(
            "http_status IS NULL OR (http_status >= 100 AND http_status <= 599)",
            name="ck_service_release_observations_http_status",
        ),
        sa.CheckConstraint(
            "consecutive_failures >= 0",
            name="ck_service_release_observations_failures",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "object_id",
            "object_instance_id",
            "provider",
            name="uq_service_release_observations_identity",
        ),
    )
    op.create_index(
        "ix_service_release_observations_object",
        "service_release_observations",
        ["object_id", "object_instance_id"],
    )

    op.create_table(
        "service_release_check_leases",
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
            name="ck_service_release_leases_provider",
        ),
        sa.CheckConstraint(
            "(lease_owner IS NULL AND lease_expires_at IS NULL) OR "
            "(lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)",
            name="ck_service_release_leases_lease_pair",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "object_id",
            "object_instance_id",
            name="uq_service_release_leases_identity",
        ),
    )
    op.create_index(
        "ix_service_release_leases_due",
        "service_release_check_leases",
        ["due_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_service_release_leases_due",
        table_name="service_release_check_leases",
    )
    op.drop_table("service_release_check_leases")
    op.drop_index(
        "ix_service_release_observations_object",
        table_name="service_release_observations",
    )
    op.drop_table("service_release_observations")
