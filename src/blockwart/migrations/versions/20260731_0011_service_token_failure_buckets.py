"""add shared service-token failure buckets

Revision ID: 20260731_0011
Revises: 20260731_0010
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260731_0011"
down_revision: str | Sequence[str] | None = "20260731_0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "service_token_failure_buckets",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("dimension", sa.String(length=16), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("window_start", sa.DateTime(), nullable=False),
        sa.Column("failure_count", sa.Integer(), server_default="1", nullable=False),
        sa.Column("event_emitted", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "dimension IN ('global','source','token')",
            name="ck_service_token_failure_buckets_dimension",
        ),
        sa.CheckConstraint(
            "failure_count >= 1",
            name="ck_service_token_failure_buckets_count",
        ),
        sa.CheckConstraint(
            "event_emitted IN (true, false)",
            name="ck_service_token_failure_buckets_event_boolean",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "dimension",
            "key_hash",
            "window_start",
            name="uq_service_token_failure_bucket_key",
        ),
    )
    op.create_index(
        "ix_service_token_failure_buckets_expiry",
        "service_token_failure_buckets",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_service_token_failure_buckets_expiry",
        table_name="service_token_failure_buckets",
    )
    op.drop_table("service_token_failure_buckets")
