"""add append-only object comments and service-token audiences

Revision ID: 20260804_0014
Revises: 20260801_0013
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from uuid import UUID, uuid5

import sqlalchemy as sa
from alembic import op

revision: str = "20260804_0014"
down_revision: str | Sequence[str] | None = "20260801_0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_LEGACY_NAMESPACE = UUID("ab7a2da4-b30f-4a4c-9bbb-c37f418ba9e7")


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        raise RuntimeError("object-comment migration requires SQLite")

    preflight_rows = _legacy_comment_rows(bind, include_instance_id=False)
    # Validate every row before the first schema or data mutation.
    for row in preflight_rows:
        raw_data = row["data_json"]
        try:
            data = json.loads(raw_data)
        except (TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"object-comment migration rejected invalid data_json for {row['id']}"
            ) from exc
        if not isinstance(data, Mapping):
            raise RuntimeError(
                f"object-comment migration rejected non-object data_json for {row['id']}"
            )
        if "comment" in data and not isinstance(data["comment"], str):
            raise RuntimeError(
                f"object-comment migration rejected non-string legacy comment for {row['id']}"
            )

    with op.batch_alter_table("catalog_objects", recreate="always") as batch:
        batch.add_column(
            sa.Column(
                "instance_id",
                sa.String(length=32),
                nullable=False,
                server_default=sa.text("(lower(hex(randomblob(16))))"),
            )
        )
        batch.create_unique_constraint(
            "uq_catalog_objects_instance_id",
            ["instance_id"],
        )

    with op.batch_alter_table("service_tokens", recreate="always") as batch:
        batch.add_column(
            sa.Column(
                "audience",
                sa.String(length=16),
                nullable=False,
                server_default="api",
            )
        )
        batch.create_check_constraint(
            "ck_service_tokens_audience",
            "audience IN ('api','mcp')",
        )

    op.create_table(
        "object_comments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("object_id", sa.String(length=128), nullable=False),
        sa.Column("object_instance_id", sa.String(length=32), nullable=False),
        sa.Column("object_created_at", sa.DateTime(), nullable=False),
        sa.Column("author_principal_id", sa.String(length=36), nullable=True),
        sa.Column("author_login", sa.String(length=128), nullable=True),
        sa.Column("author_display_name", sa.String(length=255), nullable=True),
        sa.Column("author_principal_type", sa.String(length=32), nullable=True),
        sa.Column("origin", sa.String(length=16), nullable=False),
        sa.Column("format", sa.String(length=16), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "origin IN ('ui','api','mcp','legacy')",
            name="ck_object_comments_origin",
        ),
        sa.CheckConstraint(
            "format IN ('markdown','plain_text')",
            name="ck_object_comments_format",
        ),
        sa.CheckConstraint(
            "origin = 'legacy' OR length(body) > 0",
            name="ck_object_comments_body_nonempty",
        ),
        sa.CheckConstraint(
            "format <> 'markdown' OR length(body) <= 4000",
            name="ck_object_comments_markdown_length",
        ),
        sa.CheckConstraint(
            "(origin = 'legacy' AND format = 'plain_text' "
            "AND author_principal_id IS NULL AND author_login IS NULL "
            "AND author_display_name IS NULL AND author_principal_type IS NULL) OR "
            "(origin <> 'legacy' AND format = 'markdown' "
            "AND author_principal_id IS NOT NULL AND author_login IS NOT NULL "
            "AND author_display_name IS NOT NULL AND author_principal_type IS NOT NULL)",
            name="ck_object_comments_attribution",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_object_comments_instance_created",
        "object_comments",
        [
            "object_id",
            "object_instance_id",
            "object_created_at",
            "created_at",
            "id",
        ],
    )

    legacy_rows = _legacy_comment_rows(bind, include_instance_id=True)
    for row in legacy_rows:
        data = json.loads(row["data_json"])
        if "comment" not in data:
            continue
        body = data.pop("comment")
        created_at = row["created_at"]
        stable_id = str(
            uuid5(
                _LEGACY_NAMESPACE,
                f"{row['id']}\x00{created_at}\x00{body}",
            )
        )
        bind.execute(
            sa.text(
                "INSERT INTO object_comments "
                "(id, object_id, object_instance_id, object_created_at, "
                "author_principal_id, "
                "author_login, author_display_name, author_principal_type, origin, "
                "format, body, created_at) VALUES "
                "(:id, :object_id, :object_instance_id, :object_created_at, "
                "NULL, NULL, "
                "NULL, NULL, 'legacy', 'plain_text', "
                ":body, :created_at)"
            ),
            {
                "id": stable_id,
                "object_id": row["id"],
                "object_instance_id": row["instance_id"],
                "object_created_at": created_at,
                "body": body,
                "created_at": row["updated_at"] or created_at,
            },
        )
        bind.execute(
            sa.text(
                "UPDATE catalog_objects SET data_json=:data_json, revision=revision+1 "
                "WHERE id=:object_id"
            ),
            {
                "data_json": _canonical_json(data),
                "object_id": row["id"],
            },
        )

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


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        raise RuntimeError("object-comment migration requires SQLite")
    count = bind.scalar(sa.text("SELECT COUNT(*) FROM object_comments"))
    if int(count or 0) != 0:
        raise RuntimeError(
            "object comments cannot be downgraded while comments exist; "
            "restore the paired pre-migration backup"
        )
    op.execute("DROP TRIGGER object_comments_no_update")
    op.execute("DROP TRIGGER object_comments_no_delete")
    op.drop_index(
        "ix_object_comments_instance_created",
        table_name="object_comments",
    )
    op.drop_table("object_comments")
    with op.batch_alter_table("service_tokens", recreate="always") as batch:
        batch.drop_constraint("ck_service_tokens_audience", type_="check")
        batch.drop_column("audience")
    with op.batch_alter_table("catalog_objects", recreate="always") as batch:
        batch.drop_constraint("uq_catalog_objects_instance_id", type_="unique")
        batch.drop_column("instance_id")


def _legacy_comment_rows(
    bind: sa.Connection,
    *,
    include_instance_id: bool,
) -> list[Mapping[str, object]]:
    instance_column = ", instance_id" if include_instance_id else ""
    return list(
        bind.execute(
            sa.text(
                "SELECT id, data_json, created_at, updated_at"
                f"{instance_column} FROM catalog_objects ORDER BY id"
            )
        ).mappings()
    )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
