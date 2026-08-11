"""add source snapshot, entry, and object mapping registry

Revision ID: 20260811_0016
Revises: 20260806_0015

The revision is purely additive. It creates three new tables and touches no
existing table, column, index, trigger, or row, so an upgrade from a populated
pre-#142 database preserves every catalog object, relationship, comment,
provenance header, grant, and principal byte-for-byte.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260811_0016"
down_revision: str | Sequence[str] | None = "20260806_0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CLASSIFICATIONS = (
    "'operational','retired','historical','research','migration','generated','ignored'"
)
_INTENTS = "'expect_object','no_catalog_object'"
_REASONS = (
    "'operational_inventory','retired_asset','historical_record','research_material',"
    "'migration_artifact','generated_artifact','explicitly_ignored','not_infrastructure',"
    "'unclassified'"
)
_PRESENCES = "'present','absent'"
_ROLES = "'primary','derived'"


def upgrade() -> None:
    op.create_table(
        "source_snapshots",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("collector", sa.String(length=64), nullable=False),
        sa.Column("collected_at", sa.DateTime(), nullable=False),
        sa.Column("entry_count", sa.Integer(), nullable=False),
        sa.Column("mapping_count", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(digest) = 64",
            name="ck_source_snapshots_digest_length",
        ),
        sa.CheckConstraint(
            "entry_count >= 0 AND mapping_count >= 0",
            name="ck_source_snapshots_counts_non_negative",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "digest",
            "collected_at",
            name="uq_source_snapshots_digest_collected",
        ),
    )
    op.create_index(
        "ix_source_snapshots_collected",
        "source_snapshots",
        ["collected_at", "digest"],
    )

    op.create_table(
        "source_entries",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("source_uri", sa.String(length=512), nullable=False),
        sa.Column("entry_id", sa.String(length=256), nullable=True),
        sa.Column("entry_key", sa.String(length=256), nullable=False),
        sa.Column("classification", sa.String(length=32), nullable=False),
        sa.Column("intent", sa.String(length=32), nullable=False),
        sa.Column("decision_reason", sa.String(length=32), nullable=False),
        sa.Column("presence", sa.String(length=16), nullable=False),
        sa.Column("entry_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("source_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("observed_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            f"classification IN ({_CLASSIFICATIONS})",
            name="ck_source_entries_classification",
        ),
        sa.CheckConstraint(
            f"intent IN ({_INTENTS})",
            name="ck_source_entries_intent",
        ),
        sa.CheckConstraint(
            f"decision_reason IN ({_REASONS})",
            name="ck_source_entries_decision_reason",
        ),
        sa.CheckConstraint(
            f"presence IN ({_PRESENCES})",
            name="ck_source_entries_presence",
        ),
        sa.CheckConstraint(
            "length(entry_fingerprint) = 64 AND length(source_fingerprint) = 64",
            name="ck_source_entries_fingerprint_length",
        ),
        sa.CheckConstraint(
            "length(source_uri) BETWEEN 1 AND 512",
            name="ck_source_entries_uri_length",
        ),
        sa.CheckConstraint(
            "(entry_id IS NULL AND entry_key = '') OR entry_id = entry_key",
            name="ck_source_entries_key_normalized",
        ),
        sa.ForeignKeyConstraint(
            ["snapshot_id"],
            ["source_snapshots.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "snapshot_id",
            "source_uri",
            "entry_key",
            name="uq_source_entries_identity",
        ),
        sa.UniqueConstraint(
            "id",
            "snapshot_id",
            name="uq_source_entries_row_snapshot",
        ),
    )
    op.create_index(
        "ix_source_entries_snapshot_order",
        "source_entries",
        ["snapshot_id", "source_uri", "entry_key"],
    )

    # No foreign key to catalog_objects: a deleted object must stay observable
    # as an orphaned catalog reference instead of silently disappearing.
    op.create_table(
        "source_entry_mappings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("entry_row_id", sa.Integer(), nullable=False),
        sa.Column("object_id", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("imported_entry_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("imported_at", sa.DateTime(), nullable=True),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint(
            f"role IN ({_ROLES})",
            name="ck_source_entry_mappings_role",
        ),
        sa.CheckConstraint(
            "length(imported_entry_fingerprint) = 64",
            name="ck_source_entry_mappings_fingerprint_length",
        ),
        sa.ForeignKeyConstraint(
            ["snapshot_id"],
            ["source_snapshots.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["entry_row_id", "snapshot_id"],
            ["source_entries.id", "source_entries.snapshot_id"],
            ondelete="CASCADE",
            name="fk_source_entry_mappings_entry_snapshot",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "entry_row_id",
            "object_id",
            name="uq_source_entry_mappings_edge",
        ),
    )
    op.create_index(
        "ix_source_entry_mappings_object",
        "source_entry_mappings",
        ["snapshot_id", "object_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_source_entry_mappings_object",
        table_name="source_entry_mappings",
    )
    op.drop_table("source_entry_mappings")
    op.drop_index(
        "ix_source_entries_snapshot_order",
        table_name="source_entries",
    )
    op.drop_table("source_entries")
    op.drop_index(
        "ix_source_snapshots_collected",
        table_name="source_snapshots",
    )
    op.drop_table("source_snapshots")
