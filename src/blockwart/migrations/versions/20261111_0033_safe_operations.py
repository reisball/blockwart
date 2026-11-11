"""Value-free Safe operation intents. Refs #335."""
import sqlalchemy as sa
from alembic import op

revision = "20261111_0033"
down_revision = "20261028_0032"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("safe_operations",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("channel", sa.String(32), nullable=False),
        sa.Column("object_id", sa.String(128), nullable=False),
        sa.Column("instance_id", sa.String(64), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("cas", sa.Integer(), nullable=False),
        sa.Column("source_version", sa.Integer(), nullable=True),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("result_version", sa.Integer(), nullable=True),
        sa.CheckConstraint("state IN ('intent','dispatched','succeeded','conflict','failed')",
                           name="ck_safe_operation_state"))


def downgrade():
    # Losing ambiguous-write custody would make an old client replay unsafe.
    if op.get_bind().execute(sa.text("SELECT COUNT(*) FROM safe_operations")).scalar():
        raise RuntimeError("Retain Safe operation custody before downgrade")
    op.drop_table("safe_operations")
