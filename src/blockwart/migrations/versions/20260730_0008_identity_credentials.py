"""add principals and revocable credentials

Revision ID: 20260730_0008
Revises: 20260729_0007
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260730_0008"
down_revision: str | Sequence[str] | None = "20260729_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "principals",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("principal_type", sa.String(length=32), nullable=False),
        sa.Column(
            "login",
            sa.String(length=128).with_variant(
                sa.String(length=128, collation="NOCASE"),
                "sqlite",
            ),
            nullable=False,
        ),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column(
            "active",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
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
            "active IN (true, false)",
            name="ck_principals_active_boolean",
        ),
        sa.CheckConstraint(
            "principal_type IN ('human','service_account')",
            name="ck_principals_type",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("login", name="uq_principals_login"),
    )
    op.create_index("ix_principals_active", "principals", ["active"])
    op.create_index("ix_principals_principal_type", "principals", ["principal_type"])

    op.create_table(
        "password_credentials",
        sa.Column("principal_id", sa.String(length=36), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["principal_id"],
            ["principals.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("principal_id"),
    )

    op.create_table(
        "browser_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("principal_id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("csrf_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            "expires_at > created_at",
            name="ck_browser_sessions_expiry",
        ),
        sa.ForeignKeyConstraint(
            ["principal_id"],
            ["principals.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "token_hash",
            name="uq_browser_sessions_token_hash",
        ),
    )
    op.create_index(
        "ix_browser_sessions_expires_at",
        "browser_sessions",
        ["expires_at"],
    )
    op.create_index(
        "ix_browser_sessions_principal_active",
        "browser_sessions",
        ["principal_id", "revoked_at", "expires_at"],
    )

    op.create_table(
        "login_challenges",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "expires_at > created_at",
            name="ck_login_challenges_expiry",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "token_hash",
            name="uq_login_challenges_token_hash",
        ),
    )
    op.create_index(
        "ix_login_challenges_expires_at",
        "login_challenges",
        ["expires_at"],
    )

    op.create_table(
        "service_tokens",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("principal_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("token_prefix", sa.String(length=24), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("rotated_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["principal_id"],
            ["principals.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "principal_id",
            "name",
            name="uq_service_tokens_principal_name",
        ),
        sa.UniqueConstraint(
            "token_hash",
            name="uq_service_tokens_token_hash",
        ),
    )
    op.create_index(
        "ix_service_tokens_expires_at",
        "service_tokens",
        ["expires_at"],
    )
    op.create_index(
        "ix_service_tokens_principal_active",
        "service_tokens",
        ["principal_id", "revoked_at", "expires_at"],
    )

    op.create_table(
        "security_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("principal_id", sa.String(length=36), nullable=True),
        sa.Column("event_type", sa.String(length=96), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column(
            "details_json",
            sa.Text(),
            server_default="{}",
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "channel IN ('ui','api','mcp','cli','system')",
            name="ck_security_events_channel",
        ),
        sa.CheckConstraint(
            "outcome IN ('success','failure','denied')",
            name="ck_security_events_outcome",
        ),
        sa.ForeignKeyConstraint(
            ["principal_id"],
            ["principals.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_security_events_channel", "security_events", ["channel"])
    op.create_index("ix_security_events_created_at", "security_events", ["created_at"])
    op.create_index("ix_security_events_event_type", "security_events", ["event_type"])
    op.create_index("ix_security_events_outcome", "security_events", ["outcome"])
    op.create_index(
        "ix_security_events_principal_created",
        "security_events",
        ["principal_id", "created_at"],
    )


def downgrade() -> None:
    raise RuntimeError(
        "identity and credential data cannot be downgraded safely; "
        "restore the paired pre-upgrade backup"
    )
