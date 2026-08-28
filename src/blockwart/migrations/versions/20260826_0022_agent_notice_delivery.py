"""add the agent notice delivery tables

Revision ID: 20260826_0022
Revises: 20260825_0021

The revision is purely additive. It creates four new tables (agent delivery
targets, notice subscriptions, notice events, delivery jobs) plus one redacted
attempt-audit table and touches no existing table, column, index, constraint,
trigger, or row.

No routing data is written by this migration: an upgraded catalog has zero
agent targets and zero subscriptions, so no outbound agent notification can
occur until a platform administrator deliberately creates both.

The downgrade drops exactly the five tables this revision created; it is a
clean rollback of the schema. Only notice state — all of which is re-derivable
from fresh release checks — is removed. Before a live rollback, stop Blockwart
and restore the verified pre-upgrade database according to the deployment
recovery contract.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260826_0022"
down_revision: str | Sequence[str] | None = "20260825_0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_EVENT_TYPES = "'release_update_available'"
_TRANSPORTS = "'openclaw_test_gateway'"
_SCOPES = "'object','catalog'"
_STATUSES = "'pending','delivered','failed','suppressed','expired','acknowledged'"
_ERROR_CODES = (
    "'transport_timeout','transport_unavailable','rate_limited',"
    "'target_inactive','principal_inactive','subscription_revoked',"
    "'read_permission_lost','ttl_expired','attempt_limit_reached',"
    "'storm_suppressed'"
)
_ATTEMPT_OUTCOMES = "'success','timeout','unavailable','rate_limited'"


def upgrade() -> None:
    op.create_table(
        "agent_delivery_targets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column(
            "principal_id",
            sa.String(length=36),
            sa.ForeignKey("principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("label", sa.String(length=128), nullable=False),
        sa.Column("route", sa.String(length=191), nullable=False),
        sa.Column("transport", sa.String(length=32), nullable=False),
        sa.Column("active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            f"transport IN ({_TRANSPORTS})",
            name="ck_agent_delivery_targets_transport",
        ),
        sa.CheckConstraint(
            "active IN (true, false)",
            name="ck_agent_delivery_targets_active_boolean",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_agent_delivery_targets_principal",
        "agent_delivery_targets",
        ["principal_id", "active"],
    )

    op.create_table(
        "agent_notice_subscriptions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("object_id", sa.String(length=128), nullable=True),
        sa.Column(
            "principal_id",
            sa.String(length=36),
            sa.ForeignKey("principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "target_id",
            sa.String(length=36),
            sa.ForeignKey("agent_delivery_targets.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_by_principal_id",
            sa.String(length=36),
            sa.ForeignKey("principals.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            f"event_type IN ({_EVENT_TYPES})",
            name="ck_agent_notice_subscriptions_event_type",
        ),
        sa.CheckConstraint(f"scope IN ({_SCOPES})", name="ck_agent_notice_subscriptions_scope"),
        sa.CheckConstraint(
            "active IN (true, false)",
            name="ck_agent_notice_subscriptions_active_boolean",
        ),
        sa.CheckConstraint(
            "scope <> 'object' OR object_id IS NOT NULL",
            name="ck_agent_notice_subscriptions_object_scope_anchor",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_agent_notice_subscriptions_routing",
        "agent_notice_subscriptions",
        ["event_type", "active"],
    )

    op.create_table(
        "agent_notice_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("payload_version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("object_id", sa.String(length=128), nullable=False),
        sa.Column("dedupe_key", sa.String(length=191), nullable=False),
        sa.Column("latest_tag", sa.String(length=128), nullable=True),
        sa.Column("latest_version", sa.String(length=64), nullable=True),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            f"event_type IN ({_EVENT_TYPES})",
            name="ck_agent_notice_events_event_type",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "event_type",
            "object_id",
            "dedupe_key",
            name="uq_agent_notice_events_identity",
        ),
    )
    op.create_index(
        "ix_agent_notice_events_object",
        "agent_notice_events",
        ["object_id", "occurred_at"],
    )

    op.create_table(
        "agent_delivery_jobs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column(
            "event_id",
            sa.String(length=36),
            sa.ForeignKey("agent_notice_events.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "target_id",
            sa.String(length=36),
            sa.ForeignKey("agent_delivery_targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "subscription_id",
            sa.String(length=36),
            sa.ForeignKey("agent_notice_subscriptions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=16), server_default="pending", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("claimed_by", sa.String(length=64), nullable=True),
        sa.Column("claimed_at", sa.DateTime(), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(), nullable=True),
        sa.Column("delivered_at", sa.DateTime(), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        sa.Column("suppressed_at", sa.DateTime(), nullable=True),
        sa.Column("last_error_code", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(f"status IN ({_STATUSES})", name="ck_agent_delivery_jobs_status"),
        sa.CheckConstraint(
            "last_error_code IS NULL OR last_error_code IN (" + _ERROR_CODES + ")",
            name="ck_agent_delivery_jobs_error_code",
        ),
        sa.CheckConstraint("attempts >= 0", name="ck_agent_delivery_jobs_attempts"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id", "target_id", name="uq_agent_delivery_jobs_identity"),
    )
    op.create_index(
        "ix_agent_delivery_jobs_due",
        "agent_delivery_jobs",
        ["status", "next_attempt_at"],
    )
    op.create_index(
        "ix_agent_delivery_jobs_target",
        "agent_delivery_jobs",
        ["target_id", "status"],
    )

    op.create_table(
        "agent_delivery_attempts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column(
            "job_id",
            sa.Integer(),
            sa.ForeignKey("agent_delivery_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("attempt_no", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("error_code", sa.String(length=32), nullable=True),
        sa.Column("attempted_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            f"outcome IN ({_ATTEMPT_OUTCOMES})",
            name="ck_agent_delivery_attempts_outcome",
        ),
        sa.CheckConstraint(
            "error_code IS NULL OR error_code IN (" + _ERROR_CODES + ")",
            name="ck_agent_delivery_attempts_error_code",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_agent_delivery_attempts_job",
        "agent_delivery_attempts",
        ["job_id", "attempt_no"],
    )


def downgrade() -> None:
    op.drop_index("ix_agent_delivery_attempts_job", table_name="agent_delivery_attempts")
    op.drop_table("agent_delivery_attempts")
    op.drop_index("ix_agent_delivery_jobs_target", table_name="agent_delivery_jobs")
    op.drop_index("ix_agent_delivery_jobs_due", table_name="agent_delivery_jobs")
    op.drop_table("agent_delivery_jobs")
    op.drop_index("ix_agent_notice_events_object", table_name="agent_notice_events")
    op.drop_table("agent_notice_events")
    op.drop_index(
        "ix_agent_notice_subscriptions_routing",
        table_name="agent_notice_subscriptions",
    )
    op.drop_table("agent_notice_subscriptions")
    op.drop_index("ix_agent_delivery_targets_principal", table_name="agent_delivery_targets")
    op.drop_table("agent_delivery_targets")
