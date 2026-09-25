"""Add an independent project-creation capability to principals.

Revision ID: 20260925_0024
Revises: 20260909_0023

Existing exclusive project_creator roles retain their role and are backfilled
with the new capability. Catalog owner/viewer roles and all object grants are
untouched. Downgrade refuses to discard any independent capability.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260925_0024"
down_revision: str | Sequence[str] | None = "20260909_0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "principals",
        sa.Column(
            "project_creator",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.execute(
        "UPDATE principals SET project_creator = true WHERE catalog_role = 'project_creator'"
    )


def downgrade() -> None:
    connection = op.get_bind()
    independent = connection.scalar(
        sa.text(
            "SELECT COUNT(*) FROM principals WHERE project_creator = true "
            "AND (catalog_role IS NULL OR catalog_role <> 'project_creator')"
        )
    )
    if independent:
        raise RuntimeError("cannot downgrade while independent project_creator grants exist")
    op.drop_column("principals", "project_creator")
