"""initial catalog tables

Revision ID: 20260516_0001
Revises:
Create Date: 2026-05-16
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260516_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "catalog_objects",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("data_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_catalog_objects_kind", "catalog_objects", ["kind"])
    op.create_index("ix_catalog_objects_label", "catalog_objects", ["label"])

    op.create_table(
        "relationships",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("from_ref", sa.String(length=192), nullable=False),
        sa.Column("relation_type", sa.String(length=96), nullable=False),
        sa.Column("to_ref", sa.String(length=192), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_relationships_from_ref", "relationships", ["from_ref"])
    op.create_index("ix_relationships_relation_type", "relationships", ["relation_type"])
    op.create_index("ix_relationships_to_ref", "relationships", ["to_ref"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("object_id", sa.String(length=128), nullable=True),
        sa.Column("action", sa.String(length=96), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_events_object_id", "audit_events", ["object_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_object_id", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index("ix_relationships_to_ref", table_name="relationships")
    op.drop_index("ix_relationships_relation_type", table_name="relationships")
    op.drop_index("ix_relationships_from_ref", table_name="relationships")
    op.drop_table("relationships")
    op.drop_index("ix_catalog_objects_label", table_name="catalog_objects")
    op.drop_index("ix_catalog_objects_kind", table_name="catalog_objects")
    op.drop_table("catalog_objects")
