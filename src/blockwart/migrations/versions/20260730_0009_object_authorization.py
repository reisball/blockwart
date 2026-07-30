"""add object grants and monotone object revisions

Revision ID: 20260730_0009
Revises: 20260730_0008
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260730_0009"
down_revision: str | Sequence[str] | None = "20260730_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("catalog_objects", recreate="always") as batch_op:
        batch_op.add_column(
            sa.Column(
                "revision",
                sa.Integer(),
                server_default=sa.text("1"),
                nullable=False,
            )
        )
        batch_op.create_check_constraint(
            "ck_catalog_objects_revision_positive",
            "revision >= 1",
        )

    op.create_table(
        "object_grants",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("principal_id", sa.String(length=36), nullable=False),
        sa.Column("object_id", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("created_by_principal_id", sa.String(length=36), nullable=True),
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
            "role IN "
            "('discoverer','viewer','editor','creator','access_manager','owner')",
            name="ck_object_grants_role",
        ),
        sa.CheckConstraint(
            "scope IN ('self','subtree')",
            name="ck_object_grants_scope",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_principal_id"],
            ["principals.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["object_id"],
            ["catalog_objects.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["principal_id"],
            ["principals.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "principal_id",
            "object_id",
            "role",
            "scope",
            name="uq_object_grants_assignment",
        ),
    )
    op.create_index(
        "ix_object_grants_object_principal",
        "object_grants",
        ["object_id", "principal_id"],
    )
    op.create_index(
        "ix_object_grants_principal_role_scope",
        "object_grants",
        ["principal_id", "role", "scope"],
    )


def downgrade() -> None:
    raise RuntimeError(
        "object authorization data cannot be downgraded safely; "
        "restore the paired pre-upgrade backup"
    )
