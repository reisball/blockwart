"""Index the activity feed's timestamp and tie-breaker order.

Revision ID: 20260926_0025
Revises: 20260925_0024
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "20260926_0025"
down_revision: str | Sequence[str] | None = "20260925_0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("ix_audit_events_created_at_id", "audit_events", ["created_at", "id"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_created_at_id", table_name="audit_events")
