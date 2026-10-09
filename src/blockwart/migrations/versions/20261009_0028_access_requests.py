"""add access requests, temporary grant expiry, and the request hint outbox

Revision ID: 20261009_0028
Revises: 20261009_0027

The revision is purely additive for existing rows. It adds one nullable
column (``object_grants.expires_at``), the ``access_requests`` table, and the
durable access-request hint outbox (``access_request_notices`` plus its
redacted ``access_request_notice_attempts``). Existing grants keep
``expires_at = NULL``, which means permanent, so an upgrade from a populated
database preserves every catalog object, relationship, comment, provenance
header, grant, principal, source-coverage row, health observation, monitoring
lease, and agent notice row byte-for-byte. It follows the PR221 agent notice
revision ``20261009_0027`` linearly, so the combined history keeps exactly one
Alembic head.

Database-backed invariants (identical on SQLite and PostgreSQL):

- at most one *pending* request per requester, object, role and scope (a
  partial unique index). Approved requests are deliberately outside it: the
  grant they created, not the request row, decides whether access still
  exists, so an expired or revoked approval can never block a replacement;
- one hint notice per ``(request, target)``; and
- a lease/fencing-token pair that must be consistent and can only be held by
  a ``pending`` notice.

No routing data is written: an upgraded catalog has no hint notice, and none
is created until an administrator-approved delivery target exists *and* the
deployment explicitly enables access-request hints.

The downgrade drops exactly the structures this revision created. It fails
closed while any grant still carries an expiry (expired or not): dropping the
column would silently turn those temporary Viewer grants into permanent ones.
Revoke them first. Only access-request history — which is re-derivable by
asking again — and hint notices are removed; the audit trail is untouched, so
export it before rolling back a live deployment.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261009_0028"
down_revision: str | Sequence[str] | None = "20261009_0027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STATUSES = "'pending','approved','denied','cancelled','expired','revoked'"
_NOTICE_STATUSES = "'pending','delivered','failed','suppressed','expired'"
_NOTICE_ERROR_CODES = (
    "'transport_timeout','transport_unavailable','rate_limited',"
    "'target_inactive','principal_inactive','manage_access_lost',"
    "'request_not_pending','ttl_expired','attempt_limit_reached','storm_suppressed',"
    "'delivery_error'"
)
_ATTEMPT_OUTCOMES = (
    "'success','confirmed_duplicate','timeout','unavailable','rate_limited','lease_expired'"
)


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
        sa.Column("ended_at", sa.DateTime(), nullable=True),
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
    op.create_index("ix_access_requests_status", "access_requests", ["status"])
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
    op.create_index("ix_access_requests_grant", "access_requests", ["grant_id"])
    op.create_index(
        "uq_access_requests_open",
        "access_requests",
        ["requester_principal_id", "object_id", "role", "scope"],
        unique=True,
        sqlite_where=sa.text("status = 'pending'"),
        postgresql_where=sa.text("status = 'pending'"),
    )

    op.create_table(
        "access_request_notices",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column(
            "request_id",
            sa.String(length=36),
            sa.ForeignKey("access_requests.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "target_id",
            sa.String(length=36),
            sa.ForeignKey("agent_delivery_targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "recipient_principal_id",
            sa.String(length=36),
            sa.ForeignKey("principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("claimed_by", sa.String(length=64), nullable=True),
        sa.Column("claimed_at", sa.DateTime(), nullable=True),
        sa.Column("lease_token", sa.String(length=32), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(), nullable=True),
        sa.Column("delivered_at", sa.DateTime(), nullable=True),
        sa.Column("suppressed_at", sa.DateTime(), nullable=True),
        sa.Column("last_error_code", sa.String(length=32), nullable=True),
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
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            f"status IN ({_NOTICE_STATUSES})",
            name="ck_access_request_notices_status",
        ),
        sa.CheckConstraint(
            f"last_error_code IS NULL OR last_error_code IN ({_NOTICE_ERROR_CODES})",
            name="ck_access_request_notices_error_code",
        ),
        sa.CheckConstraint("attempts >= 0", name="ck_access_request_notices_attempts"),
        sa.CheckConstraint(
            "(lease_token IS NULL) = (lease_expires_at IS NULL)",
            name="ck_access_request_notices_lease_pair",
        ),
        sa.CheckConstraint(
            "status = 'pending' OR lease_token IS NULL",
            name="ck_access_request_notices_terminal_unleased",
        ),
        sa.UniqueConstraint(
            "request_id",
            "target_id",
            name="uq_access_request_notices_identity",
        ),
    )
    op.create_index(
        "ix_access_request_notices_due",
        "access_request_notices",
        ["status", "next_attempt_at"],
    )
    op.create_index(
        "ix_access_request_notices_request",
        "access_request_notices",
        ["request_id", "status"],
    )
    op.create_table(
        "access_request_notice_attempts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column(
            "notice_id",
            sa.String(length=36),
            sa.ForeignKey("access_request_notices.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("attempt_no", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(length=24), nullable=False),
        sa.Column("error_code", sa.String(length=32), nullable=True),
        sa.Column("attempted_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            f"outcome IN ({_ATTEMPT_OUTCOMES})",
            name="ck_access_request_notice_attempts_outcome",
        ),
        sa.CheckConstraint(
            f"error_code IS NULL OR error_code IN ({_NOTICE_ERROR_CODES})",
            name="ck_access_request_notice_attempts_error_code",
        ),
    )
    op.create_index(
        "ix_access_request_notice_attempts_notice",
        "access_request_notice_attempts",
        ["notice_id", "attempt_no"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    temporary = bind.execute(
        sa.text("SELECT COUNT(*) FROM object_grants WHERE expires_at IS NOT NULL")
    ).scalar_one()
    if temporary:
        raise RuntimeError(
            "Temporary grants must be explicitly revoked before downgrade: dropping "
            "object_grants.expires_at would otherwise make them permanent"
        )
    op.drop_index(
        "ix_access_request_notice_attempts_notice",
        table_name="access_request_notice_attempts",
    )
    op.drop_table("access_request_notice_attempts")
    op.drop_index("ix_access_request_notices_request", table_name="access_request_notices")
    op.drop_index("ix_access_request_notices_due", table_name="access_request_notices")
    op.drop_table("access_request_notices")
    op.drop_index("uq_access_requests_open", table_name="access_requests")
    op.drop_index("ix_access_requests_grant", table_name="access_requests")
    op.drop_index("ix_access_requests_requester_created", table_name="access_requests")
    op.drop_index("ix_access_requests_object_status", table_name="access_requests")
    op.drop_index("ix_access_requests_status", table_name="access_requests")
    op.drop_table("access_requests")
    op.drop_index("ix_object_grants_expires_at", table_name="object_grants")
    op.drop_column("object_grants", "expires_at")
