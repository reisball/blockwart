"""add access requests and temporary grant expiry

Revision ID: 20260826_0023
Revises: 20260825_0021

The revision is purely additive for existing rows.  It adds one nullable
column (``object_grants.expires_at``), one new table (``access_requests``)
and their indexes.  Existing grants keep ``expires_at = NULL``, which means
permanent under the request-path expiry rule, so an upgrade from a populated
pre-#100 database preserves every catalog object, relationship, comment,
provenance header, grant, principal, source-coverage row, health observation,
and monitoring lease byte-for-byte.

The partial unique index ``uq_access_requests_open`` enforces at most one open
(pending or approved) access request per requester, object, role and scope.
SQLite and PostgreSQL both support partial unique indexes; the dialect-specific
where clauses are attached below.

The downgrade drops exactly the structures this revision created.  Only the
access-request history — which is re-derivable by asking again — is removed;
no pre-existing structure is restored, altered, or re-derived.  Because the
downgrade also drops ``access_requests.grant_id`` history together with the
table, operators should export the audit trail before rolling back a live
deployment.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260826_0023"
down_revision: str | Sequence[str] | None = "20260825_0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STATUSES = "'pending','approved','denied','cancelled','expired'"


def upgrade() -> None:
    op.add_column(
        "object_grants",
        sa.Column("expires_at", sa.DateTime(), nullable=True),
    )
    op.create_index(
        "ix_object_grants_expires_at",
        "object_grants",
        ["expires_at"],
    )
    op.create_table(
        "access_requests",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "requester_principal_id",
            sa.String(length=36),
            sa.ForeignKey("principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "object_id",
            sa.String(length=128),
            sa.ForeignKey("catalog_objects.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="viewer"),
        sa.Column("scope", sa.String(length=16), nullable=False, server_default="self"),
        sa.Column(
            "duration",
            sa.String(length=16),
            nullable=False,
            server_default="temporary",
        ),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("requested_expires_at", sa.DateTime(), nullable=True),
        sa.Column("approved_expires_at", sa.DateTime(), nullable=True),
        sa.Column(
            "decided_by_principal_id",
            sa.String(length=36),
            sa.ForeignKey("principals.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("decided_at", sa.DateTime(), nullable=True),
        sa.Column(
            "grant_id",
            sa.Integer(),
            sa.ForeignKey("object_grants.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "notification_attempts",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("last_notification_at", sa.DateTime(), nullable=True),
        sa.Column("last_notification_outcome", sa.String(length=32), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            f"status IN ({_STATUSES})",
            name="ck_access_requests_status",
        ),
        sa.CheckConstraint(
            "role IN ('viewer')",
            name="ck_access_requests_role_v1",
        ),
        sa.CheckConstraint(
            "scope IN ('self')",
            name="ck_access_requests_scope_v1",
        ),
        sa.CheckConstraint(
            "duration IN ('temporary','permanent')",
            name="ck_access_requests_duration",
        ),
    )
    op.create_index(
        "ix_access_requests_status",
        "access_requests",
        ["status"],
    )
    op.create_index(
        "ix_access_requests_object_status",
        "access_requests",
        ["object_id", "status"],
    )
    op.create_index(
        "ix_access_requests_requester_created",
        "access_requests",
        ["requester_principal_id", "created_at"],
    )
    op.create_index(
        "uq_access_requests_open",
        "access_requests",
        ["requester_principal_id", "object_id", "role", "scope"],
        unique=True,
        sqlite_where=sa.text("status IN ('pending', 'approved')"),
        postgresql_where=sa.text("status IN ('pending', 'approved')"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_access_requests_open",
        table_name="access_requests",
    )
    op.drop_index(
        "ix_access_requests_requester_created",
        table_name="access_requests",
    )
    op.drop_index(
        "ix_access_requests_object_status",
        table_name="access_requests",
    )
    op.drop_index("ix_access_requests_status", table_name="access_requests")
    op.drop_table("access_requests")
    op.drop_index("ix_object_grants_expires_at", table_name="object_grants")
    op.drop_column("object_grants", "expires_at")
