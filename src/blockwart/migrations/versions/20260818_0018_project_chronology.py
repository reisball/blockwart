"""add curated Project chronology kinds

Revision ID: 20260818_0018
Revises: 20260818_0017
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260818_0018"
down_revision: str | Sequence[str] | None = "20260818_0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_KIND_CHECK = (
    "project_chronology_kind IS NULL OR project_chronology_kind IN "
    "('intent','implementation','result','decision','milestone','blocker','note')"
)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS object_comments_no_update")
        op.execute("DROP TRIGGER IF EXISTS object_comments_no_delete")
        with op.batch_alter_table("object_comments", recreate="always") as batch:
            batch.add_column(
                sa.Column(
                    "project_chronology_kind",
                    sa.String(length=24),
                    nullable=True,
                )
            )
            batch.create_check_constraint(
                "ck_object_comments_project_chronology_kind",
                _KIND_CHECK,
            )
        _create_sqlite_append_only_triggers()
    else:
        op.add_column(
            "object_comments",
            sa.Column(
                "project_chronology_kind",
                sa.String(length=24),
                nullable=True,
            ),
        )
        op.create_check_constraint(
            "ck_object_comments_project_chronology_kind",
            "object_comments",
            _KIND_CHECK,
        )


def downgrade() -> None:
    bind = op.get_bind()
    typed_count = bind.scalar(
        sa.text(
            "SELECT COUNT(*) FROM object_comments "
            "WHERE project_chronology_kind IS NOT NULL"
        )
    )
    if int(typed_count or 0) != 0:
        raise RuntimeError(
            "Project chronology cannot be downgraded while typed entries exist; "
            "restore the paired pre-migration backup"
        )
    if bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS object_comments_no_update")
        op.execute("DROP TRIGGER IF EXISTS object_comments_no_delete")
        with op.batch_alter_table("object_comments", recreate="always") as batch:
            batch.drop_constraint(
                "ck_object_comments_project_chronology_kind",
                type_="check",
            )
            batch.drop_column("project_chronology_kind")
        _create_sqlite_append_only_triggers()
    else:
        op.drop_constraint(
            "ck_object_comments_project_chronology_kind",
            "object_comments",
            type_="check",
        )
        op.drop_column("object_comments", "project_chronology_kind")


def _create_sqlite_append_only_triggers() -> None:
    op.execute(
        "CREATE TRIGGER object_comments_no_update "
        "BEFORE UPDATE ON object_comments BEGIN "
        "SELECT RAISE(ABORT, 'object comments are append-only'); END"
    )
    op.execute(
        "CREATE TRIGGER object_comments_no_delete "
        "BEFORE DELETE ON object_comments BEGIN "
        "SELECT RAISE(ABORT, 'object comments are append-only'); END"
    )
