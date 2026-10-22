"""Bind monitoring evidence and leases to their acquisition target. Refs #269."""
import sqlalchemy as sa
from alembic import op

revision = "20261022_0029"
down_revision = "20261022_0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ("service_observations", "service_check_leases"):
        op.add_column(table, sa.Column("target_fingerprint", sa.String(64), nullable=True))


def downgrade() -> None:
    for table in ("service_check_leases", "service_observations"):
        op.drop_column(table, "target_fingerprint")
