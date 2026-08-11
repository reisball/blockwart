from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from blockwart.db.base import Base

# The controlled vocabularies are duplicated as SQL CHECK constraints on
# purpose: the database refuses an out-of-vocabulary classification, intent,
# reason, presence, or role even if a future writer bypasses the domain layer.
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


class SourceSnapshot(Base):
    """One immutable, digest-bound source collection result.

    A snapshot stores inventory facts only: stable URIs, stable entry IDs,
    controlled classifications, opaque fingerprints, and timestamps. It never
    stores source text, secrets, or arbitrary private file content.
    """

    __tablename__ = "source_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "digest",
            "collected_at",
            name="uq_source_snapshots_digest_collected",
        ),
        CheckConstraint(
            "length(digest) = 64",
            name="ck_source_snapshots_digest_length",
        ),
        CheckConstraint(
            "entry_count >= 0 AND mapping_count >= 0",
            name="ck_source_snapshots_counts_non_negative",
        ),
        Index(
            "ix_source_snapshots_collected",
            "collected_at",
            "digest",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    collector: Mapped[str] = mapped_column(String(64), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    entry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    mapping_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class SourceEntry(Base):
    """One configured source entry inside exactly one snapshot."""

    __tablename__ = "source_entries"
    __table_args__ = (
        UniqueConstraint(
            "snapshot_id",
            "source_uri",
            "entry_key",
            name="uq_source_entries_identity",
        ),
        CheckConstraint(
            f"classification IN ({_CLASSIFICATIONS})",
            name="ck_source_entries_classification",
        ),
        CheckConstraint(
            f"intent IN ({_INTENTS})",
            name="ck_source_entries_intent",
        ),
        CheckConstraint(
            f"decision_reason IN ({_REASONS})",
            name="ck_source_entries_decision_reason",
        ),
        CheckConstraint(
            f"presence IN ({_PRESENCES})",
            name="ck_source_entries_presence",
        ),
        CheckConstraint(
            "length(entry_fingerprint) = 64 AND length(source_fingerprint) = 64",
            name="ck_source_entries_fingerprint_length",
        ),
        CheckConstraint(
            "length(source_uri) BETWEEN 1 AND 512",
            name="ck_source_entries_uri_length",
        ),
        CheckConstraint(
            "(entry_id IS NULL AND entry_key = '') OR entry_id = entry_key",
            name="ck_source_entries_key_normalized",
        ),
        UniqueConstraint(
            "id",
            "snapshot_id",
            name="uq_source_entries_row_snapshot",
        ),
        Index(
            "ix_source_entries_snapshot_order",
            "snapshot_id",
            "source_uri",
            "entry_key",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("source_snapshots.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    # `entry_id` is optional; `entry_key` is its total-order normalization
    # ("" when absent) so the identity constraint stays enforceable in SQLite.
    entry_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    entry_key: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    classification: Mapped[str] = mapped_column(String(32), nullable=False)
    intent: Mapped[str] = mapped_column(String(32), nullable=False)
    decision_reason: Mapped[str] = mapped_column(String(32), nullable=False)
    presence: Mapped[str] = mapped_column(String(16), nullable=False, default="present")
    entry_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    source_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class SourceEntryMapping(Base):
    """One explicit many-to-many edge from a source entry to a catalog object.

    This table is the mapping registry. ``CatalogProvenance.source_ref`` stays
    object provenance and is never overloaded as a mapping registry. The edge
    intentionally has no database foreign key to ``catalog_objects``: a deleted
    object must remain observable as ``orphaned_catalog_reference`` instead of
    silently disappearing.
    """

    __tablename__ = "source_entry_mappings"
    __table_args__ = (
        UniqueConstraint(
            "entry_row_id",
            "object_id",
            name="uq_source_entry_mappings_edge",
        ),
        CheckConstraint(
            f"role IN ({_ROLES})",
            name="ck_source_entry_mappings_role",
        ),
        CheckConstraint(
            "length(imported_entry_fingerprint) = 64",
            name="ck_source_entry_mappings_fingerprint_length",
        ),
        ForeignKeyConstraint(
            ["entry_row_id", "snapshot_id"],
            ["source_entries.id", "source_entries.snapshot_id"],
            ondelete="CASCADE",
            name="fk_source_entry_mappings_entry_snapshot",
        ),
        Index(
            "ix_source_entry_mappings_object",
            "snapshot_id",
            "object_id",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("source_snapshots.id", ondelete="CASCADE"),
        nullable=False,
    )
    entry_row_id: Mapped[int] = mapped_column(Integer, nullable=False)
    object_id: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="primary")
    imported_entry_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
