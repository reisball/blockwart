"""establish the controlled Alembic schema lifecycle

Revision ID: 20260723_0002
Revises: 20260516_0001
Create Date: 2026-07-23
"""

from collections.abc import Sequence

revision: str = "20260723_0002"
down_revision: str | None = "20260516_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Mark databases that entered the controlled Alembic lifecycle."""


def downgrade() -> None:
    """Return only the lifecycle marker to the initial schema revision."""
